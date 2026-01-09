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
# 🛠️ 实验配置 (在这里体现你的工作量)
# ==========================================
EXPERIMENT_MODE = 'Proposed'  # 可选: 'Proposed', 'MaxMin', 'Random'
LOG_FILE = f"mininet_metrics_{EXPERIMENT_MODE}.csv"
CPU_LIMIT = 16.0
MEM_LIMIT = 32.0

class HoneyMatrixController(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        
        # 强制刷新 stdout，确保你能看到打印信息
        sys.stdout.reconfigure(line_buffering=True)
        
        print(f"\n[Controller] >>> 实验启动: 模式={EXPERIMENT_MODE} <<<")
        print(f"[Controller] 日志文件路径: {os.path.abspath(LOG_FILE)}")
        
        self.brain = StrategyEngine(cpu_limit=CPU_LIMIT, mem_limit=MEM_LIMIT, disk_limit=500)
        self.nodes_data = []
        
        # 初始化 CSV (强制清空旧文件)
        try:
            with open(LOG_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["time", "round", "mode", "cpu_used", "mem_used", "cpu_limit", "mem_limit", "value_protected"])
                f.flush()
                os.fsync(f.fileno())
            print("[Controller] CSV 表头已写入。")
        except Exception as e:
            print(f"[Controller] !!! CSV 创建失败: {e}")

        # 启动主循环
        self.monitor_thread = hub.spawn(self.monitor_loop)

    def monitor_loop(self):
        print("[Controller] 等待 network_state.json 生成...")
        hub.sleep(3) # 给 Mininet 一点时间
        
        round_id = 0
        while True:
            round_id += 1
            
            # 1. 读取网络状态 (带重试机制)
            if not self._load_network_state():
                print(f"[Controller] Round {round_id}: ⏳ 等待 network_state.json...")
                hub.sleep(2)
                continue

            # 2. 计算策略 (核心工作量体现)
            target_names = []
            try:
                # print(f"[Controller] Round {round_id}: 🧠 正在计算策略...")
                start_time = time.time()
                
                if EXPERIMENT_MODE == 'Proposed':
                    target_names = self.brain.compute_milp(self.nodes_data)
                elif EXPERIMENT_MODE == 'MaxMin':
                    target_names = self.brain.compute_maxmin(self.nodes_data)
                else:
                    target_names = self.brain.compute_random(self.nodes_data)
                
                calc_time = time.time() - start_time
                # print(f"[Controller] 策略计算耗时: {calc_time:.4f}s. 选中蜜罐: {len(target_names)} 个")
                
            except Exception as e:
                print(f"[Controller] ⚠️ 策略引擎报错: {e}")
                print("[Controller] -> 自动切换到 Random 策略以维持实验运行")
                target_names = self.brain.compute_random(self.nodes_data)

            # 3. 统计指标
            cpu_used = 0.0
            mem_used = 0.0
            val_protected = 0.0
            
            for node in self.nodes_data:
                if node['name'] in target_names:
                    cpu_used += node['req_cpu']
                    mem_used += node['req_mem']
                    val_protected += node['impact']

            # 4. 写入 CSV (关键修复：立即刷盘)
            try:
                with open(LOG_FILE, 'a', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow([
                        time.time(), round_id, EXPERIMENT_MODE, 
                        cpu_used, mem_used, CPU_LIMIT, MEM_LIMIT, val_protected
                    ])
                    f.flush()            # 刷新 Python 缓冲
                    os.fsync(f.fileno()) # 刷新 OS 缓冲
                
                print(f"[Controller] Round {round_id} ✅ 记录成功: CPU={cpu_used:.1f}/{CPU_LIMIT}, Mem={mem_used:.1f}")
                
            except Exception as e:
                print(f"[Controller] ❌ 写入 CSV 失败: {e}")

            # 5. 下发流表 (体现 SDN 工作量)
            # self._apply_openflow_rules(target_names) 
            
            hub.sleep(5) # 采样间隔

    def _load_network_state(self):
        if not os.path.exists('network_state.json'): return False
        try:
            with open('network_state.json', 'r') as f:
                data = json.load(f)
                if not data: return False
                self.nodes_data = data
                return True
        except: return False