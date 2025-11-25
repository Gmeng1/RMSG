from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub

from strategy_engine import StrategyEngine
# 为了简单，我们复用 data_loader 来生成同样的节点列表
# 在真实部署中，控制器应该通过网络发现拓扑，但仿真实验中共享配置是标准做法
from data_loader import CVEDataLoader 

class HoneyMatrixController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        
        # 1. 初始化大脑
        self.brain = StrategyEngine(total_resource_budget=10) # 设定一个中等预算
        
        # 2. 加载网络资产数据 (模拟已知拓扑)
        # 注意：这里需要重新生成一遍完全一样的节点数据，或者在 topo 文件里存下来传给 controller
        # 为了演示，我们这里简化处理：假设我们知道节点 IP 和 Value
        # 实际操作中，建议把 experiment_topo.py 生成的节点列表保存为 nodes.json，这里读取
        self.nodes_data = self._load_nodes_config()
        
        # 3. 启动博弈循环
        self.game_thread = hub.spawn(self.game_loop)

    def _load_nodes_config(self):
        # 模拟从配置文件读取的节点列表
        # 这里为了演示代码能跑，我手动构造几个和 Topo 对应的
        # ！！！请确保这里的 Name 和 IP 与 experiment_topo.py 里生成的一致！！！
        # 你可以修改 experiment_topo.py，让它在启动时把生成的节点信息 dump 到 'network_state.json'
        # 然后在这里 json.load('network_state.json')
        return [
            {'name': 'dmz_1', 'ip': '10.0.2.11', 'impact': 9.8, 'prob': 0.39, 'cost': 5},
            {'name': 'dmz_2', 'ip': '10.0.2.12', 'impact': 9.4, 'prob': 0.39, 'cost': 5},
            {'name': 'office_1', 'ip': '10.0.5.11', 'impact': 7.0, 'prob': 0.20, 'cost': 1},
            # ... 更多节点
        ]

    def game_loop(self):
        """主循环：每隔 20 秒执行一次 Stackelberg 博弈"""
        while True:
            self.logger.info("\n[Game Loop] Calculating new defense strategy...")
            
            # 1. 调用 Gurobi 计算
            honeypot_nodes = self.brain.compute_optimal_placement(self.nodes_data)
            
            # 2. 提取蜜点 IP 列表
            honey_ips = [n for n in self.nodes_data if n['name'] in honeypot_nodes]
            # 这里简化逻辑：我们只打印出来，表示“流表已下发”
            # 在真实 Ryu 代码中，这里需要调用 self.add_flow 把发往 honey_ips 的流量
            # 修改 output action 指向蜜罐服务器
            
            self.logger.info(f"[Defend] Active Honeypots: {honeypot_nodes}")
            
            hub.sleep(20) # 20秒一轮

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 安装 Table-miss 流表 (默认泛洪)
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # ... 这里省略 packet_in 处理函数 (实现二层交换)，你可以直接复制 Ryu 的 simple_switch_13.py ...
    # 只要保证网络能通即可