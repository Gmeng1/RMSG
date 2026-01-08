import pandas as pd
import numpy as np
import random
import time
import os

class AttackerAgent:
    def __init__(self, transition_matrix_path, targets_dict):
        """
        初始化攻击智能体
        :param transition_matrix_path: 转移矩阵 CSV 文件路径
        :param targets_dict: 目标列表 {'ip': {'zone': '...', 'services': [...]}}
        """
        self.targets = list(targets_dict.keys())
        self.current_state = "Benign"
        
        # 1. 加载转移矩阵
        if os.path.exists(transition_matrix_path):
            try:
                self.matrix = pd.read_csv(transition_matrix_path, index_col=0)
                self.states = self.matrix.columns.tolist()
                print(f"[AttackerAgent] Loaded matrix with states: {self.states}")
            except Exception as e:
                print(f"[AttackerAgent] Error loading matrix: {e}")
                self._use_fallback_matrix()
        else:
            print(f"[AttackerAgent] Warning: {transition_matrix_path} not found.")
            self._use_fallback_matrix()

    def _use_fallback_matrix(self):
        """备用矩阵（防止文件缺失导致崩溃）"""
        self.states = ["Benign", "PortScan", "BruteForce", "WebAttack", "DoS", "Botnet"]
        # 创建一个简单的单位矩阵作为备用，防止报错
        self.matrix = pd.DataFrame(np.eye(len(self.states)), index=self.states, columns=self.states)

    def execute_action(self, host_node=None):
        """
        执行一步动作：根据转移概率选择下一个状态
        :param host_node: Mininet主机对象 (在真实脚本中通常传None，只做逻辑模拟)
        """
        # 1. 状态转移 (Markov Chain)
        if self.current_state in self.matrix.index:
            probs = self.matrix.loc[self.current_state].values
            # 归一化处理，防止浮点数误差导致 sum != 1
            if probs.sum() > 0:
                probs = probs / probs.sum()
                next_state = np.random.choice(self.states, p=probs)
            else:
                next_state = "Benign"
        else:
            next_state = "Benign"

        self.current_state = next_state
        
        # 2. 执行动作 (模拟或真实)
        if self.current_state != "Benign":
            target = random.choice(self.targets)
            timestamp = time.strftime("%H:%M:%S")
            
            # 打印日志 (会被重定向到 attacker.log)
            print(f"[{timestamp}] [Attacker] State: {self.current_state} -> Target: {target}")
            
            # [可选] 这里可以添加真实的 os.system 调用
            # if self.current_state == "PortScan":
            #     os.system(f"nmap -sS {target} &")
        
        return self.current_state