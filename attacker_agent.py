import csv
import random
import time
import os

class AttackerAgent:
    def __init__(self, transition_matrix_path, targets_dict):
        """
        零依赖版本的攻击智能体 (No Pandas, No Numpy)
        """
        self.targets = list(targets_dict.keys())
        self.current_state = "Benign"
        
        # 存储转移概率字典: {'Benign': [0.8, 0.2, ...], 'PortScan': [...]}
        self.transitions = {}
        self.states = []
        
        # 1. 加载 CSV (使用标准库 csv)
        if os.path.exists(transition_matrix_path):
            try:
                with open(transition_matrix_path, 'r', encoding='utf-8') as f:
                    reader = csv.reader(f)
                    # 读取表头: ['', 'Benign', 'PortScan', 'BruteForce', ...]
                    header = next(reader)
                    # 过滤掉第一个空字符串，获取状态列表
                    self.states = [s for s in header if s.strip()]
                    
                    # 读取每一行概率
                    for row in reader:
                        if not row: continue
                        src_state = row[0]
                        # 将后续的概率字符串转为浮点数
                        probs = [float(x) for x in row[1:]]
                        self.transitions[src_state] = probs
                        
                print(f"[AttackerAgent] Matrix Loaded. States: {self.states}")
            except Exception as e:
                print(f"[AttackerAgent] Error loading CSV: {e}")
                self._use_fallback()
        else:
            print(f"[AttackerAgent] Warning: {transition_matrix_path} not found.")
            self._use_fallback()

    def _use_fallback(self):
        """备用逻辑，防止文件缺失导致崩溃"""
        self.states = ["Benign", "Attack"]
        self.transitions = {
            "Benign": [0.5, 0.5],
            "Attack": [0.5, 0.5]
        }

    def execute_action(self, host_node=None):
        """
        执行一步动作：根据转移概率选择下一个状态
        """
        # 1. 状态转移 (Markov Chain)
        if self.current_state in self.transitions:
            weights = self.transitions[self.current_state]
            # Python 3.6+ 支持 random.choices (加权随机)
            # weights 列表会自动归一化，无需 numpy
            try:
                next_state = random.choices(self.states, weights=weights, k=1)[0]
            except ValueError:
                # 防止概率全为0的情况
                next_state = "Benign"
        else:
            next_state = "Benign"

        self.current_state = next_state
        
        # 2. 模拟攻击行为 (打印日志)
        if self.current_state != "Benign":
            # 随机选择一个目标
            target = random.choice(self.targets) if self.targets else "Unknown"
            timestamp = time.strftime("%H:%M:%S")
            
            # 这个 print 会被重定向到 attacker.log
            print(f"[{timestamp}] [Attacker] State: {self.current_state} -> Target: {target}")
            
            # [模拟真实负载] 
            # 如果需要让 CPU 曲线有波动，可以在这里加一点计算负载
            # x = [i**2 for i in range(1000)] 
        
        return self.current_state