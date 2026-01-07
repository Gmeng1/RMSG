import json
import time
import csv
import os
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub

# 引入你的策略引擎
from strategy_engine import StrategyEngine

# 配置
EXPERIMENT_MODE = 'Proposed' # 可选: 'Proposed', 'MaxMin', 'Random'
LOG_FILE = f"mininet_metrics_{EXPERIMENT_MODE}.csv"
CPU_LIMIT = 16.0  # 设置一个严格的限制
MEM_LIMIT = 32.0

class HoneyMatrixController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        # 初始化策略引擎
        self.brain = StrategyEngine(cpu_limit=CPU_LIMIT, mem_limit=MEM_LIMIT, disk_limit=500)
        self.nodes_data = []
        
        # 初始化日志
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(["time", "round", "mode", "cpu_used", "mem_used", "cpu_limit", "mem_limit", "protected_value"])

        # 加载节点数据
        try:
            with open('network_state.json', 'r') as f:
                self.nodes_data = json.load(f)
        except:
            pass # 等待 Topo 生成

        self.game_thread = hub.spawn(self.monitor_loop)

    def monitor_loop(self):
        hub.sleep(5)
        round_id = 0
        while True:
            round_id += 1
            if not self.nodes_data:
                # 尝试重新加载
                try:
                    with open('network_state.json', 'r') as f: self.nodes_data = json.load(f)
                except: pass
                hub.sleep(2)
                continue

            # 1. 计算策略
            target_names = []
            if EXPERIMENT_MODE == 'Proposed':
                # 尝试调用 MILP，如果没装 Gurobi 会报错，记得处理
                try:
                    target_names = self.brain.compute_milp(self.nodes_data)
                except:
                    # Fallback if compute_milp missing or failing
                    target_names = self.brain.compute_random(self.nodes_data)
            elif EXPERIMENT_MODE == 'MaxMin':
                target_names = self.brain.compute_maxmin(self.nodes_data)
            else:
                target_names = self.brain.compute_random(self.nodes_data)

            # 2. 计算资源消耗 (监控核心)
            cpu_used = 0.0
            mem_used = 0.0
            protected_val = 0.0
            
            for node in self.nodes_data:
                if node['name'] in target_names:
                    cpu_used += node['req_cpu']
                    mem_used += node['req_mem']
                    protected_val += node['impact']

            # 3. 记录数据
            self.logger.info(f"Round {round_id} [{EXPERIMENT_MODE}]: CPU={cpu_used}/{CPU_LIMIT}, Mem={mem_used}/{MEM_LIMIT}")
            
            with open(LOG_FILE, 'a', newline='') as f:
                writer = csv.writer(f)
                writer.writerow([time.time(), round_id, EXPERIMENT_MODE, cpu_used, mem_used, CPU_LIMIT, MEM_LIMIT, protected_val])

            # 4. (可选) 下发流表逻辑...
            
            hub.sleep(5) # 5秒采样一次