# data_loader.py (升级版)
import json
import random

class CVEDataLoader:
    def __init__(self, json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            self.pool = json.load(f)

    def get_random_vuln(self, zone_type, min_score=0.0, max_score=10.0):
        """
        根据区域类型 (zone_type) 自动分配多维资源属性
        """
        # 1. 筛选漏洞 (同之前逻辑)
        candidates = [v for v in self.pool if min_score <= v['impact_score'] <= max_score]
        if not candidates:
            selected = random.choice(self.pool)
        else:
            selected = random.choice(candidates)
        
        # 2. 赋予多维资源属性 (核心修改)
        # 复制一份防止修改原数据
        vuln_data = selected.copy()
        
        if zone_type == 'dmz':
            # 高交互
            vuln_data['req_cpu'] = 4
            vuln_data['req_mem'] = 8
            vuln_data['req_disk'] = 50
            vuln_data['type'] = 'High-Interaction'
        elif zone_type in ['ops', 'biz']:
            # 中交互
            vuln_data['req_cpu'] = 2
            vuln_data['req_mem'] = 4
            vuln_data['req_disk'] = 20
            vuln_data['type'] = 'Medium-Interaction'
        else: # office
            # 低交互
            vuln_data['req_cpu'] = 1
            vuln_data['req_mem'] = 0.5
            vuln_data['req_disk'] = 5
            vuln_data['type'] = 'Low-Interaction'
            
        return vuln_data