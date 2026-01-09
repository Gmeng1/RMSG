import json
import os
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSKernelSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel
from data_loader import CVEDataLoader

class FourZoneTopo(Topo):
    def build(self):
        # 初始化数据加载器
        # 确保 processed_cve_pool.json 在同一目录下
        self.loader = CVEDataLoader("processed_cve_pool.json")
        
        # 1. 创建交换机
        # dpid 必须是 16位 hex 字符串，这里简化处理
        core_sw = self.addSwitch('s1', dpid='0000000000000001')
        dmz_sw = self.addSwitch('s2', dpid='0000000000000002')
        ops_sw = self.addSwitch('s3', dpid='0000000000000003')
        biz_sw = self.addSwitch('s4', dpid='0000000000000004')
        office_sw = self.addSwitch('s5', dpid='0000000000000005')

        # 连接区域到核心交换机
        self.addLink(dmz_sw, core_sw)
        self.addLink(ops_sw, core_sw)
        self.addLink(biz_sw, core_sw)
        self.addLink(office_sw, core_sw)

        # 2. 部署各区域节点
        # 参数: (交换机, 区域前缀/类型, 数量, 最小CVSS分数, 最大CVSS分数)
        self._add_zone_hosts(dmz_sw, "dmz", count=3, min_score=9.0)
        self._add_zone_hosts(biz_sw, "biz", count=5, min_score=7.5, max_score=9.0)
        self._add_zone_hosts(ops_sw, "ops", count=2, min_score=8.0)
        self._add_zone_hosts(office_sw, "office", count=10, max_score=7.0)

    def _add_zone_hosts(self, switch, prefix, count, min_score=0.0, max_score=10.0):
        for i in range(1, count + 1):
            name = f"{prefix}_{i}"
            
            # 从 data_loader 获取一个随机漏洞配置
            # 注意：prefix (如 "dmz") 会作为 zone_type 传入，从而决定 CPU/Mem 消耗
            vuln_info = self.loader.get_random_vuln(prefix, min_score, max_score)
            
            # 将属性保存在 Mininet 节点的 params 中
            node_params = {
                'ip': f'10.0.{switch[1]}.{i+10}', 
                # [Fix] 这里修改为 'impact_score'，对应 JSON 文件中的 key
                'impact_val': vuln_info['impact_score'], 
                'exploit_prob': vuln_info['exploit_prob'],
                # [Feature] 添加资源需求，供控制器监控
                'req_cpu': vuln_info.get('req_cpu', 1.0),
                'req_mem': vuln_info.get('req_mem', 1.0),
                # 攻击成本 (true_att_cost) 暂时用 deploy_cost 模拟，如果 JSON 里没有就默认 2.0
                'deploy_cost': vuln_info.get('deploy_cost', 2.0),
                'cve_id': vuln_info['cve_id']
            }
            
            # 添加主机
            self.addHost(name, **node_params)
            self.addLink(name, switch)

def run_experiment():
    topo = FourZoneTopo()
    # 使用 RemoteController 连接 Ryu (默认端口 6633/6653)
    net = Mininet(topo=topo, controller=RemoteController, switch=OVSKernelSwitch)
    net.start()
    
    print("\n=== 1. Exporting Network State for Controller ===")
    nodes_data = []
    for host in net.hosts:
        # 跳过交换机(s开头)和控制器(c开头)
        if 's' in host.name or 'c' in host.name: continue
        
        # 导出节点信息供控制器读取
        node_info = {
            'name': host.name,
            'ip': host.IP(),
            'impact': host.params.get('impact_val', 0),
            'prob': host.params.get('exploit_prob', 0),
            'req_cpu': host.params.get('req_cpu', 0),
            'req_mem': host.params.get('req_mem', 0),
            'true_att_cost': host.params.get('deploy_cost', 0)
        }
        nodes_data.append(node_info)
    
    # 保存状态文件
    abs_path = "/home/gjj/RMSG/network_state.json"
    
    print(f"\n[Mininet] Writing state to: {abs_path}")
    with open(abs_path, 'w') as f:
        json.dump(nodes_data, f, indent=4)
    print("Saved network_state.json")

    os.chmod(abs_path, 0o666)
    print(f"[Mininet] Permissions set to 666. Saved successfully.")

    print("\n=== 2. Setting up Attacker ===")
    # 假设 office_1 是攻击者起点
    attacker = net.get('office_1') 
    
    # 启动攻击脚本 (后台运行)
    print(f"Starting attacker script on {attacker.name}...")
    # 确保 run_attacker_node.py 在同一目录
    attacker.cmd('python3 run_attacker_node.py > attacker.log 2>&1 &')

    print("\n=== 3. Ready! Please start Ryu Controller now ===")
    print("Run this command in another terminal:")
    print("ryu-manager honey_controller.py")
    
    # 进入 Mininet CLI 方便手动测试
    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_experiment()