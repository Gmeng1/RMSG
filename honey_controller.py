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
# 请务必确认这个绝对路径是你 Mininet 生成文件的位置
STATE_FILE = "/home/gjj/RMSG/network_state.json" 
LOG_FILE = f"mininet_metrics_{EXPERIMENT_MODE}.csv"
CPU_LIMIT = 16.0
MEM_LIMIT = 32.0

class HoneyMatrixController(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        
        # 1. 强制刷新打印缓冲区 (让你能实时看到每一行日志)
        sys.stdout.reconfigure(line_buffering=True)
        
        print(f"\n[Init] >>> 控制器启动 <<<")
        print(f"[Init] 监控文件: {STATE_FILE}")
        
        self.brain = StrategyEngine(cpu_limit=CPU_LIMIT, mem_limit=MEM_LIMIT, disk_limit=500)
        self.nodes_data = []
        
        # 2. 初始化 CSV
        self._init_csv()

        # 3. 启动主循环
        print("[Init] 正在启动监控线程...")
        self.monitor_thread = hub.spawn(self.monitor_loop)

    def _init_csv(self):
        try:
            with open(LOG_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["time", "round", "mode", "cpu_used", "mem_used", "cpu_limit", "mem_limit", "value_protected"])
                f.flush()
                os.fsync(f.fileno())
            print("[Init] CSV 表头写入成功。")
        except Exception as e:
            print(f"[Init] ❌ CSV 创建失败: {e}")

    def monitor_loop(self):
        print("[Loop] 线程已运行，等待 2s...")
        hub.sleep(2) 
        
        round_id = 0
        while True:
            # >>>>>>>> 🛡️ 绝对防崩溃外壳 (Start) <<<<<<<<
            try:
                round_id += 1
                print(f"\n--- [Round {round_id}] 开始 ---")

                # Step 1: 读取文件 (带重试)
                if not self._load_network_state_safe():
                    print(f"[Round {round_id}] ⏳ 没读到文件，跳过本轮...")
                    hub.sleep(2)
                    continue

                # Step 2: 计算策略
                target_names = []
                try:
                    # print(f"[Round {round_id}] 调用策略引擎: {EXPERIMENT_MODE}")
                    if EXPERIMENT_MODE == 'Proposed':
                        target_names = self.brain.compute_milp(self.nodes_data)
                    elif EXPERIMENT_MODE == 'MaxMin':
                        target_names = self.brain.compute_maxmin(self.nodes_data)
                    else:
                        target_names = self.brain.compute_random(self.nodes_data)
                    
                    # print(f"[Round {round_id}] 策略计算完成，选中 {len(target_names)} 个节点")
                    
                except Exception as logic_e:
                    print(f"[Round {round_id}] ⚠️ 策略引擎内部报错: {logic_e}")
                    # 只要报错，就用空列表，保证实验不崩
                    target_names = []

                # Step 3: 写入 CSV
                self._record_metrics(round_id, target_names)
                
                # Step 4: 休眠 (这就是你怀疑的地方)
                print(f"[Round {round_id}] 本轮结束，准备休眠 5s...")
                hub.sleep(5)
                print(f"[Round {round_id}] 休眠醒来！准备进入下一轮...")

            except BaseException as critical_e:
                # 它可以捕获所有错误，包括 SyntaxError, KeyError, 甚至 Gurobi Crash
                print(f"\n[CRASH] 🛑 严重崩溃捕获: {critical_e}")
                import traceback
                traceback.print_exc() # 打印详细报错位置
                print("[CRASH] 正在尝试复活线程，3秒后重试...\n")
                hub.sleep(3)
            # >>>>>>>> 🛡️ 绝对防崩溃外壳 (End) <<<<<<<<

    def _load_network_state_safe(self):
        """安全读取 JSON，防止文件正在被写入时读取导致崩溃"""
        if not os.path.exists(STATE_FILE):
            # print(f"[File] 文件不存在: {STATE_FILE}")
            return False
            
        # 尝试 3 次读取，防止读到半截数据
        for attempt in range(3):
            try:
                with open(STATE_FILE, 'r') as f:
                    # 使用 f.read() 确保读到东西再解析
                    content = f.read()
                    if not content.strip(): 
                        raise ValueError("Empty File")
                    self.nodes_data = json.loads(content)
                    return True
            except (json.JSONDecodeError, ValueError) as e:
                # print(f"[File] 读取冲突 (Attempt {attempt+1}): {e}")
                hub.sleep(0.1) # 等 0.1 秒再试
            except Exception as e:
                print(f"[File] 未知读取错误: {e}")
                return False
        return False

    def _record_metrics(self, round_id, target_names):
        try:
            cpu_used = 0.0
            mem_used = 0.0
            val_protected = 0.0
            
            # 使用 .get() 防止 Key Error
            for node in self.nodes_data:
                if node['name'] in target_names:
                    cpu_used += node.get('req_cpu', 0)
                    mem_used += node.get('req_mem', 0)
                    val_protected += node.get('impact', 0)

            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([
                    time.time(), round_id, EXPERIMENT_MODE, 
                    cpu_used, mem_used, CPU_LIMIT, MEM_LIMIT, val_protected
                ])
                f.flush()
                os.fsync(f.fileno())
            
            print(f"[CSV] ✅ Round {round_id} 数据已写入 (CPU: {cpu_used})")
            
        except Exception as e:
            print(f"[CSV] ❌ 写入失败: {e}")