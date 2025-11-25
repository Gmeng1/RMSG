import json
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from data_loader import CVEDataLoader

class FourZoneTopo(Topo):
    def build(self):
        # 初始化数据加载器
        # 注意：这里路径要填对，假设 json 在同级目录
        self.loader = CVEDataLoader("processed_cve_pool.json")
        
        # 1. 创建核心交换机与区域交换机
        core_sw = self.addSwitch('s1', dpid='0000000000000001')
        dmz_sw = self.addSwitch('s2', dpid='0000000000000002')  # DMZ
        ops_sw = self.addSwitch('s3', dpid='0000000000000003')  # 运维
        biz_sw = self.addSwitch('s4', dpid='0000000000000004')  # 业务
        office_sw = self.addSwitch('s5', dpid='0000000000000005') # 办公

        # 连接区域到核心
        self.addLink(dmz_sw, core_sw)
        self.addLink(ops_sw, core_sw)
        self.addLink(biz_sw, core_sw)
        self.addLink(office_sw, core_sw)

        # 2. 部署节点并“附魔” (赋予 CVE 属性)
        
        # --- DMZ区 (高价值，高危漏洞) ---
        self._add_zone_hosts(dmz_sw, "dmz", count=3, min_score=9.0)

        # --- 业务区 (中高价值) ---
        self._add_zone_hosts(biz_sw, "biz", count=5, min_score=7.5, max_score=9.0)

        # --- 运维区 (高价值，但可能漏洞较少或特定) ---
        self._add_zone_hosts(ops_sw, "ops", count=2, min_score=8.0)

        # --- 办公区 (数量多，价值低) ---
        self._add_zone_hosts(office_sw, "office", count=10, max_score=7.0)

    def _add_zone_hosts(self, switch, prefix, count, min_score=0.0, max_score=10.0):
        for i in range(1, count + 1):
            name = f"{prefix}_{i}"
            
            # 从 1万条数据中抽取属性
            vuln_info = self.loader.get_random_vuln(min_score, max_score)
            
            # 将属性保存在 Mininet 节点的 params 字典中
            # 这些信息后续会被 Gurobi 读取用来计算最优策略
            node_params = {
                'ip': f'10.0.{switch[1]}.{i+10}', # 简易IP分配
                'impact_val': vuln_info['impact_score'],
                'exploit_prob': vuln_info['exploit_prob'],
                'deploy_cost': vuln_info['deploy_cost'],
                'cve_id': vuln_info['cve_id']
            }
            
            # 添加主机
            self.addHost(name, **node_params)
            self.addLink(name, switch)

def run_experiment():
    topo = FourZoneTopo()
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)
    net.start()
    
    print("\n=== 1. Exporting Network State for Controller ===")
    nodes_data = []
    for host in net.hosts:
        # 跳过 switch 和 controller
        if 's' in host.name or 'c' in host.name: continue
        
        node_info = {
            'name': host.name,
            'ip': host.IP(),
            'impact': host.params.get('impact_val', 0),
            'prob': host.params.get('exploit_prob', 0),
            'cost': host.params.get('deploy_cost', 0)
        }
        nodes_data.append(node_info)
    
    # 保存到文件，供 honey_controller.py 读取
    with open('network_state.json', 'w') as f:
        json.dump(nodes_data, f, indent=4)
    print("Saved network_state.json")

    print("\n=== 2. Setting up Attacker ===")
    # 假设 office_1 是内鬼/攻击起点，或者你可以专门加一个 attacker host
    attacker = net.get('office_1') 
    
    # 在后台启动攻击脚本 &
    # 注意：确保所有 py 文件都在同级目录
    print(f"Starting attacker script on {attacker.name}...")
    attacker.cmd('python3 run_attacker_node.py > attacker.log 2>&1 &')

    print("\n=== 3. Ready! Please start Ryu Controller now ===")
    print("Run this command in another terminal:")
    print("ryu-manager honey_controller.py")
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()