# honey_controller.py
# 完整版 - 包含 L2 交换机功能与 Stackelberg 动态防御逻辑

import json
import time
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
from ryu.lib import hub

# 导入策略引擎 (大脑)
from strategy_engine import StrategyEngine

class HoneyMatrixController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(HoneyMatrixController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}  # 存储所有连接的交换机
        
        # --- 1. 初始化大脑 ---
        # 资源预算设为 15 (根据你的实验需求调整)
        self.brain = StrategyEngine(total_resource_budget=15)
        
        # --- 2. 读取网络状态 (由 Mininet 导出的) ---
        try:
            with open('network_state.json', 'r') as f:
                self.nodes_data = json.load(f)
            self.logger.info(f"[Init] Loaded {len(self.nodes_data)} nodes from network_state.json")
        except FileNotFoundError:
            self.logger.error("[Error] network_state.json not found! Run experiment_topo.py first.")
            self.nodes_data = []

        # --- 3. 启动博弈循环线程 ---
        self.game_thread = hub.spawn(self.game_loop)

    def game_loop(self):
        """
        核心博弈循环：周期性重新计算蜜阵部署
        """
        # 等待交换机连接并稳定
        hub.sleep(5)
        
        round_count = 0
        while True:
            round_count += 1
            self.logger.info(f"\n=== [Round {round_count}] Calculating Defense Strategy ===")
            
            if not self.nodes_data:
                self.logger.warning("No node data available. Waiting...")
                hub.sleep(10)
                continue

            # --- A. 调用 Gurobi 计算最优部署 ---
            # 返回被选中的节点名称列表，例如 ['dmz_1', 'office_3']
            honeypot_nodes = self.brain.compute_optimal_placement(self.nodes_data)
            
            # --- B. 提取这些节点的 IP ---
            active_honey_ips = []
            for node in self.nodes_data:
                if node['name'] in honeypot_nodes:
                    active_honey_ips.append(node['ip'])
            
            self.logger.info(f"[Defend] Active Honeypots deployed at: {active_honey_ips}")
            
            # --- C. 下发流表拦截攻击 ---
            self.update_honeypot_flows(active_honey_ips)
            
            # --- D. 等待下一轮 (比如 20 秒) ---
            hub.sleep(20)

    def update_honeypot_flows(self, honey_ips):
        """
        向所有交换机下发流表：
        如果目的 IP 是蜜罐 IP，则视为被捕获 (Packet-In 到控制器记录日志)
        """
        for datapath in self.datapaths.values():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            
            for ip in honey_ips:
                # 匹配规则：IP协议，目的地址 = 蜜罐IP
                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip)
                
                # 动作：发送给控制器 (Packet-In)，且不进行转发
                # 这会造成 Ping 不通，但控制器会打印 "Attack Intercepted"
                actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
                
                # 优先级设为 100 (高于默认转发规则 1)
                self.add_flow(datapath, priority=100, match=match, actions=actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        """交换机握手，安装默认流表"""
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        # 记录 datapath 以便后续下发流表
        self.datapaths[datapath.id] = datapath
        
        # 默认流表：Packet-In (优先级 0，最低)
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

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """
        处理数据包：实现 L2 交换功能 + 蜜罐告警
        """
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        # 忽略 LLDP 包
        if eth.ethertype == 35020:
            return
        
        # --- 蜜罐捕获逻辑 ---
        # 如果是 IPv4 包，检查是否命中了我们的蜜罐规则
        # 注意：因为我们上面下发的流表 action 是 OUTPUT_CONTROLLER，所以包会来到这里
        if eth.ethertype == 0x0800:
            ip_pkt = pkt.get_protocols(ipv4.ipv4)[0]
            dst_ip = ip_pkt.dst
            
            # 如果这个 IP 在我们当前的防御列表中（需要从 nodes_data 反查或简化判断）
            # 为了演示，直接打印一条显眼的日志
            # 只有当这是攻击者发的包时才有意义
            self.logger.info(f"⚡ [ALERT] Traffic captured targeting: {dst_ip} (Possile Honeypot Hit)")

        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})

        # 学习 MAC 地址
        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # 安装普通转发流表 (优先级 1，低于蜜罐规则的 100)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self.add_flow(datapath, 1, match, actions)
        
        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)