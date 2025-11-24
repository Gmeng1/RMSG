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
    # 连接到 Ryu 控制器 (假设控制器运行在本地 6633)
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)
    
    net.start()
    print("\n=== Network Simulation Started ===")
    print("Dump node info to check CVE assignment:")
    
    # 打印几个节点验证数据是否加载成功
    for host in net.hosts:
        if 'dmz' in host.name or 'office_1' == host.name:
            print(f"Host: {host.name} | Value: {host.params.get('impact_val')} | Cost: {host.params.get('deploy_cost')} | CVE: {host.params.get('cve_id')}")

    # 这里可以启动你的 AttackerAgent 脚本
    # ...
    
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()