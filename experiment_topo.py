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
        self.loader = CVEDataLoader("processed_cve_pool.json")
        
        # 1. 创建交换机
        core_sw = self.addSwitch('s1', dpid='0000000000000001')
        dmz_sw = self.addSwitch('s2', dpid='0000000000000002')
        ops_sw = self.addSwitch('s3', dpid='0000000000000003')
        biz_sw = self.addSwitch('s4', dpid='0000000000000004')
        office_sw = self.addSwitch('s5', dpid='0000000000000005')

        self.addLink(dmz_sw, core_sw)
        self.addLink(ops_sw, core_sw)
        self.addLink(biz_sw, core_sw)
        self.addLink(office_sw, core_sw)

        # 2. 部署节点
        self._add_zone_hosts(dmz_sw, "dmz", count=3, min_score=9.0)
        self._add_zone_hosts(biz_sw, "biz", count=5, min_score=7.5, max_score=9.0)
        self._add_zone_hosts(ops_sw, "ops", count=2, min_score=8.0)
        self._add_zone_hosts(office_sw, "office", count=10, max_score=7.0)

    def _add_zone_hosts(self, switch, prefix, count, min_score=0.0, max_score=10.0):
        for i in range(1, count + 1):
            name = f"{prefix}_{i}"
            # [Fix] 传入 prefix 作为 zone_type
            vuln_info = self.loader.get_random_vuln(prefix, min_score, max_score)
            
            node_params = {
                'ip': f'10.0.{switch[1]}.{i+10}',
                'impact_val': vuln_info['impact'], # 注意 data_loader 返回的 key 可能是 impact 或 impact_score，请核对
                'exploit_prob': vuln_info['prob'],
                'deploy_cost': vuln_info.get('deploy_cost', 1.0), # 兼容性字段
                'req_cpu': vuln_info['req_cpu'],  # [New] 导出资源需求
                'req_mem': vuln_info['req_mem'],  # [New]
                'cve_id': vuln_info['cve_id']
            }
            self.addHost(name, **node_params)
            self.addLink(name, switch)

def run_experiment():
    topo = FourZoneTopo()
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)
    net.start()
    
    print("\n=== 1. Exporting Network State ===")
    nodes_data = []
    for host in net.hosts:
        if 's' in host.name or 'c' in host.name: continue
        
        # [New] 导出完整的资源信息给控制器
        node_info = {
            'name': host.name,
            'ip': host.IP(),
            'impact': host.params.get('impact_val', 0),
            'prob': host.params.get('exploit_prob', 0),
            'req_cpu': host.params.get('req_cpu', 0),
            'req_mem': host.params.get('req_mem', 0),
            'true_att_cost': host.params.get('deploy_cost', 2.0) # 借用这个字段存攻击成本
        }
        nodes_data.append(node_info)
    
    with open('network_state.json', 'w') as f:
        json.dump(nodes_data, f, indent=4)
    print("Saved network_state.json")

    print("\n=== 2. Setting up Attacker ===")
    attacker = net.get('office_1') 
    attacker.cmd('python3 run_attacker_node.py > attacker.log 2>&1 &')

    print("\n=== 3. Ready! Start Ryu Controller now ===")
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()