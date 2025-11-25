# run_attacker_node.py
import sys
import time
import os
from attacker_agent import AttackerAgent

def run_attack_simulation():
    # 1. 定义目标网络 (与 Controller 中的一致)
    targets = {
        '10.0.2.11': {'services': ['Web'], 'zone': 'DMZ'},
        '10.0.2.12': {'services': ['Web'], 'zone': 'DMZ'},
        '10.0.5.11': {'services': ['SSH'], 'zone': 'Office'},
    }
    
    # 2. 初始化智能体
    # 确保 final_transition_matrix.csv 在同一目录下
    agent = AttackerAgent("final_transition_matrix.csv", targets)
    
    print("=== Attacker Node Started ===")
    
    # 3. 循环攻击
    while True:
        action = agent.execute_action(None) # None 表示不传 Mininet Host 对象，而是直接执行
        
        # 这里我们要稍微修改 attacker_agent.py 的 execute_action
        # 让它支持 "真实执行" (Real Execution)
        # 例如：
        # if action == "Scan":
        #    os.system(f"nmap -sS {target_ip}")
        # if action == "WebAttack":
        #    os.system(f"curl -s {target_ip} > /dev/null")
        
        # 为了演示，我们先只打印日志
        time.sleep(2) # 攻击间隔

if __name__ == "__main__":
    run_attack_simulation()