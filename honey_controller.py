import json
import time
import csv
import os
import sys
from ryu.base import app_manager
from ryu.lib import hub

# 引入你的策略引擎
from strategy_engine import StrategyEngine

# ==========================================
# 🛠️ 实验配置
# ==========================================
EXPERIMENT_MODE = 'Proposed' 
LOG_FILE = f"/home/gjj/RMSG/mininet_metrics_{EXPERIMENT_MODE}.csv" # 绝对路径
STATE_FILE = "/tmp/network_state.json" # 绝对路径 (Mininet生成的那个)
CPU_LIMIT = 16.0
MEM_LIMIT = 32.0

class HoneyMatrixController(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        
        # 强制刷新打印缓冲区
        sys.stdout.reconfigure(line_buffering=True)
        
        print(f"\n[Controller] >>> 实验启动: 模式={EXPERIMENT_MODE} <<<")
        print(f"[Controller] 监控目标文件: {STATE_FILE}")
        
        # 初始化大脑
        self.brain = StrategyEngine(cpu_limit=CPU_LIMIT, mem_limit=MEM_LIMIT, disk_limit=500)
        self.nodes_data = []
        
        # 初始化 CSV
        self._init_csv()

        # 启动主循环
        self.monitor_thread = hub.spawn(self.monitor_loop)

    def _init_csv(self):
        try:
            with open(LOG_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["time", "round", "mode", "cpu_used", "mem_used", "cpu_limit", "mem_limit", "value_protected"])
                f.flush()
                os.fsync(f.fileno())
            print("[Controller] CSV 表头已写入。")
        except Exception as e:
            print(f"[Controller] !!! CSV 创建失败: {e}")

    def monitor_loop(self):
        print("[Controller] 监控线程已启动 (Thread Started)")
        hub.sleep(2) # 等待 Mininet 准备好
        
        round_id = 0
        while True:
            # >>>>>>>> 🔴 超级防崩溃外壳 (开始) <<<<<<<<
            try:
                round_id += 1
                # print(f"--- Round {round_id} Start ---") # 调试用

                # 1. 读取网络状态
                if not self._load_network_state():
                    # print(f"[Controller] Round {round_id}: 等待文件 {STATE_FILE}...")
                    hub.sleep(2)
                    continue

                # 2. 计算策略
                target_names = []
                try:
                    if EXPERIMENT_MODE == 'Proposed':
                        target_names = self.brain.compute_milp(self.nodes_data)
                    elif EXPERIMENT_MODE == 'MaxMin':
                        target_names = self.brain.compute_maxmin(self.nodes_data)
                    else:
                        target_names = self.brain.compute_random(self.nodes_data)
                except Exception as logic_error:
                    print(f"[Controller] ⚠️ 策略计算出错: {logic_error}")
                    print("[Controller] -> 降级为 Random 策略")
                    target_names = self.brain.compute_random(self.nodes_data)

                # 3. 统计并写入
                self._record_metrics(round_id, target_names)
                
                # 4. 睡眠 (关键步骤)
                # print(f"[Controller] Round {round_id} 结束，准备休眠 5s...")
                hub.sleep(5)
                # print(f"[Controller] Round {round_id} 休眠结束，进入下一轮")

            except BaseException as critical_error:
                # 这里会捕获一切错误，包括 Ctrl+C 或者 线程崩溃
                print(f"\n[Controller] 🛑 严重异常 (CRITICAL): {critical_error}")
                print("[Controller] 尝试自动恢复，3秒后重试...\n")
                hub.sleep(3)
            # >>>>>>>> 🔴 超级防崩溃外壳 (结束) <<<<<<<<

    def _record_metrics(self, round_id, target_names):
        cpu_used = 0.0
        mem_used = 0.0
        val_protected = 0.0
        
        for node in self.nodes_data:
            if node['name'] in target_names:
                cpu_used += node.get('req_cpu', 0) # 使用 get 防止报错
                mem_used += node.get('req_mem', 0)
                val_protected += node.get('impact', 0)

        try:
            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.time(), round_id, EXPERIMENT_MODE, 
                    cpu_used, mem_used, CPU_LIMIT, MEM_LIMIT, val_protected
                ])
                f.flush()
                os.fsync(f.fileno())
            print(f"[Controller] Round {round_id} ✅ 写入成功 | CPU: {cpu_used}/{CPU_LIMIT}")
        except Exception as e:
            print(f"[Controller] CSV 写入失败: {e}")

    def _load_network_state(self):
        if not os.path.exists(STATE_FILE): return False
        try:
            # 增加一个极短的重试，防止 Mininet 正在写文件时我们去读
            for _ in range(3):
                try:
                    with open(STATE_FILE, 'r') as f:
                        data = json.load(f)
                        if data:
                            self.nodes_data = data
                            return True
                except json.JSONDecodeError:
                    # 文件可能为空或正在写入，等一下重试
                    hub.sleep(0.1)
                    continue
            return False
        except: return False