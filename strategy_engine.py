# strategy_engine.py
import gurobipy as gp
from gurobipy import GRB
import random
import numpy as np

class StrategyEngine:
    def __init__(self, cpu_limit=64, mem_limit=64, disk_limit=500):
        self.cpu_limit = cpu_limit
        self.mem_limit = mem_limit
        self.disk_limit = disk_limit

    def compute_milp(self, nodes_data):
        """本文提出的 MILP 模型 """
        model = gp.Model("MILP_Model")
        model.setParam('OutputFlag', 0)
        x = model.addVars(len(nodes_data), vtype=GRB.BINARY)
        obj = gp.LinExpr()
        for i, n in enumerate(nodes_data):
            obj += x[i] * (n['impact'] * n.get('prob', 0.5))
        model.setObjective(obj, GRB.MAXIMIZE)
        
        # 多维约束
        model.addConstr(gp.quicksum(x[i] * n['req_cpu'] for i, n in enumerate(nodes_data)) <= self.cpu_limit)
        model.addConstr(gp.quicksum(x[i] * n['req_mem'] for i, n in enumerate(nodes_data)) <= self.mem_limit)
        model.addConstr(gp.quicksum(x[i] * n['req_disk'] for i, n in enumerate(nodes_data)) <= self.disk_limit)
        
        model.optimize()
        return [nodes_data[i]['name'] for i in range(len(nodes_data)) if x[i].x > 0.5] if model.status == GRB.OPTIMAL else []

    def compute_random(self, nodes_data):
        """随机部署"""
        selected = []
        indices = list(range(len(nodes_data)))
        random.shuffle(indices)
        c, m, d = 0, 0, 0
        for i in indices:
            n = nodes_data[i]
            if c + n['req_cpu'] <= self.cpu_limit and m + n['req_mem'] <= self.mem_limit and d + n['req_disk'] <= self.disk_limit:
                selected.append(n['name'])
                c += n['req_cpu']; m += n['req_mem']; d += n['req_disk']
        return selected

    def compute_fair(self, nodes_data):
        """公平分配 (均匀尝试覆盖所有节点) [cite: 558]"""
        # 公平分配在离散部署中表现为：按区域顺序轮流分配，直到资源耗尽
        selected = []
        c, m, d = 0, 0, 0
        # 将节点按区域均匀打乱，模拟“雨露均沾”
        fair_queue = sorted(nodes_data, key=lambda x: x['name']) 
        for n in fair_queue:
            if c + n['req_cpu'] <= self.cpu_limit and m + n['req_mem'] <= self.mem_limit and d + n['req_disk'] <= self.disk_limit:
                selected.append(n['name'])
                c += n['req_cpu']; m += n['req_mem']; d += n['req_disk']
        return selected

    def compute_maxmin(self, nodes_data):
        """Maxmin 策略 (优先保护最高风险节点) [cite: 145]"""
        # 按照风险（Impact * Prob）从高到低排序，尝试消除最大威胁
        sorted_nodes = sorted(nodes_data, key=lambda x: x['impact'] * x.get('prob', 0.5), reverse=True)
        selected = []
        c, m, d = 0, 0, 0
        for n in sorted_nodes:
            if c + n['req_cpu'] <= self.cpu_limit and m + n['req_mem'] <= self.mem_limit and d + n['req_disk'] <= self.disk_limit:
                selected.append(n['name'])
                c += n['req_cpu']; m += n['req_mem']; d += n['req_disk']
        return selected

    def compute_ga(self, nodes_data, generations=50, pop_size=20):
        """遗传算法 (GA) 简化版"""
        num_nodes = len(nodes_data)
        # 初始化种群
        pop = [np.random.randint(0, 2, num_nodes) for _ in range(pop_size)]
        
        def fitness(ind):
            c = sum(ind[i] * nodes_data[i]['req_cpu'] for i in range(num_nodes))
            m = sum(ind[i] * nodes_data[i]['req_mem'] for i in range(num_nodes))
            d = sum(ind[i] * nodes_data[i]['req_disk'] for i in range(num_nodes))
            if c > self.cpu_limit or m > self.mem_limit or d > self.disk_limit:
                return 0
            return sum(ind[i] * (nodes_data[i]['impact'] * nodes_data[i].get('prob', 0.5)) for i in range(num_nodes))

        for _ in range(generations):
            pop = sorted(pop, key=fitness, reverse=True)
            new_pop = pop[:5] # 精英保留
            while len(new_pop) < pop_size:
                p1, p2 = random.choices(pop[:10], k=2)
                cp = random.randint(1, num_nodes-1)
                child = np.concatenate([p1[:cp], p2[cp:]]) # 交叉
                if random.random() < 0.1: child[random.randint(0, num_nodes-1)] ^= 1 # 变异
                new_pop.append(child)
            pop = new_pop
        
        best_ind = max(pop, key=fitness)
        return [nodes_data[i]['name'] for i in range(num_nodes) if best_ind[i] == 1]
    
    def compute_economic_milp(self, nodes_data, cost_factor=1.0):
        """
        实验B专用：基于经济效用的 MILP 模型
        目标：最大化 (拦截收益 - 部署成本 - 漏防损失)
        """
        model = gp.Model("Economic_Stackelberg")
        model.setParam('OutputFlag', 0)

        x = model.addVars(len(nodes_data), vtype=GRB.BINARY, name="x")

        obj = gp.LinExpr()
        for i, n in enumerate(nodes_data):
            # 基础参数
            prob = n.get('prob', 0.5)
            impact = n['impact']
            # 假设：部署成本与该节点的资源消耗成正比 (模拟真实云环境计费)
            # cost_factor 是我们会动态调整的实验变量
            deploy_cost = (n['req_cpu'] * 1.0 + n['req_mem'] * 0.5) * cost_factor
            
            # 收益项拆解：
            # 1. 成功拦截的收益 (Reward) = Impact * Prob
            # 2. 部署的成本 (Cost) = deploy_cost
            # 3. 漏防的损失 (Loss) = Impact * Prob
            
            # 目标函数推导：
            # 如果部署 (x=1): 获得 (Reward - Cost)
            # 如果不部署 (x=0): 承受 (-Loss)
            # 合并项系数 = (Reward - Cost) - (-Loss) = Reward + Loss - Cost
            # 常数项 = -Loss
            
            term = x[i] * (impact * prob * 2 - deploy_cost) - (impact * prob)
            obj += term
            
        model.setObjective(obj, GRB.MAXIMIZE)
        
        # 这里我们可以选择是否移除硬性资源约束
        # 为了体现纯粹的“经济博弈”，建议移除硬约束，让金钱决定一切
        # 或者保留极宽的约束作为物理底线
        
        model.optimize()

        selected = []
        if model.status == GRB.OPTIMAL:
            for i, n in enumerate(nodes_data):
                if x[i].x > 0.5:
                    selected.append(n['name'])
        return selected