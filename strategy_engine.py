import gurobipy as gp
from gurobipy import GRB

class StrategyEngine:
    def __init__(self, total_resource_budget=20):
        """
        初始化策略引擎
        :param total_resource_budget: 系统总资源上限 (模拟 CPU/内存限制)
                                      假设高交互蜜罐消耗5，低交互消耗1，总共只有20单位。
        """
        self.budget = total_resource_budget
        print(f"[StrategyEngine] Initialized with Resource Budget: {self.budget}")

    def compute_optimal_placement(self, nodes_data):
        """
        使用 Gurobi 求解最优蜜阵部署策略
        :param nodes_data: 包含节点信息的列表，格式如下:
                           [{'name': 'dmz_1', 'impact': 9.8, 'prob': 0.39, 'cost': 5}, ...]
        :return: 选中的节点名称列表
        """
        # 1. 创建模型
        model = gp.Model("HoneyMatrix_Deployment")
        model.setParam('OutputFlag', 0)  # 关闭 Gurobi 繁杂的输出日志

        # 2. 创建变量
        # x[i] = 1 表示在第 i 个节点部署蜜点，0 表示不部署
        x = model.addVars(len(nodes_data), vtype=GRB.BINARY, name="Deploy")

        # 3. 设置目标函数 (Objective Function)
        # 我们希望最大化：(节点价值 * 攻击概率) 的总和
        # 解释：优先保护那些“既重要又容易被黑”的节点
        obj_expr = gp.LinExpr()
        for i, node in enumerate(nodes_data):
            # 收益 = Impact Score * Exploit Probability
            # 这符合 Stackelberg 博弈中防御者试图最大化期望效用的逻辑
            utility = node['impact'] * node['prob']
            obj_expr += x[i] * utility
        
        model.setObjective(obj_expr, GRB.MAXIMIZE)

        # 4. 设置约束条件 (Constraints)
        # 资源约束：所有部署节点的 Cost 之和 <= 总预算
        cost_expr = gp.LinExpr()
        for i, node in enumerate(nodes_data):
            cost_expr += x[i] * node['cost']
        
        model.addConstr(cost_expr <= self.budget, "Resource_Limit")

        # 区域约束 (可选)：比如要求 DMZ 区至少部署 1 个蜜点
        # 这里先注释掉，等跑通后再加
        # dmz_indices = [i for i, n in enumerate(nodes_data) if 'dmz' in n['name']]
        # model.addConstr(sum(x[i] for i in dmz_indices) >= 1, "Min_DMZ_Defense")

        # 5. 开始求解
        model.optimize()

        # 6. 解析结果
        selected_nodes = []
        if model.status == GRB.OPTIMAL:
            total_value_secured = 0
            total_cost_spent = 0
            
            for i, node in enumerate(nodes_data):
                if x[i].x > 0.5:  # 如果变量值为 1
                    selected_nodes.append(node['name'])
                    total_value_secured += node['impact']
                    total_cost_spent += node['cost']
            
            print(f"\n[Gurobi] Optimization Solved!")
            print(f"   - Budget: {self.budget} | Spent: {total_cost_spent}")
            print(f"   - Total Protected Value: {total_value_secured:.2f}")
            print(f"   - Deployed on {len(selected_nodes)} nodes: {selected_nodes}")
            
            return selected_nodes
        else:
            print("[Gurobi] No optimal solution found.")
            return []

# --- 单元测试 (Unit Test) ---
# 这部分代码让你不用启动 Mininet 也能测试 Gurobi 逻辑是否正确
if __name__ == "__main__":
    # 模拟从 Mininet 提取的数据
    mock_data = [
        {'name': 'dmz_1',    'impact': 9.8, 'prob': 0.39, 'cost': 5}, # 高价值，昂贵
        {'name': 'dmz_2',    'impact': 9.4, 'prob': 0.39, 'cost': 5},
        {'name': 'office_1', 'impact': 7.0, 'prob': 0.20, 'cost': 1}, # 低价值，便宜
        {'name': 'office_2', 'impact': 6.5, 'prob': 0.20, 'cost': 1},
        {'name': 'ops_1',    'impact': 8.5, 'prob': 0.30, 'cost': 5},
    ]

    # 测试场景：资源非常紧张 (预算只有 6)
    # 预期结果：应该会选 office_1 (1) + office_2 (1)，也许再加一个其他的？
    # 或者如果 dmz_1 的性价比极高，可能只选 dmz_1 (5)。
    # 让我们看看 AI 到底怎么算。
    print("--- Test Case: Low Budget (6) ---")
    engine = StrategyEngine(total_resource_budget=6)
    engine.compute_optimal_placement(mock_data)

    print("\n--- Test Case: High Budget (15) ---")
    engine_high = StrategyEngine(total_resource_budget=15)
    engine_high.compute_optimal_placement(mock_data)