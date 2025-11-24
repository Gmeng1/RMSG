import json
import random

class CVEDataLoader:
    def __init__(self, json_path):
        with open(json_path, 'r', encoding='utf-8') as f:
            self.pool = json.load(f)
        print(f"[DataLoader] Loaded {len(self.pool)} vulnerabilities from library.")

    def get_random_vuln(self, min_score=0.0, max_score=10.0):
        """
        随机抽取一个符合分数段的漏洞，模拟不同区域的资产价值。
        """
        candidates = [
            v for v in self.pool 
            if min_score <= v['impact_score'] <= max_score
        ]
        
        if not candidates:
            # 如果没有符合条件的，就从整个池子里随便拿一个作为兜底
            return random.choice(self.pool)
            
        selected = random.choice(candidates)
        
        # --- 关键修正：人工制造资源差异 ---
        # 如果数据里全是 High-Interaction，我们需要手动制造一些 Low-Interaction
        # 逻辑：如果漏洞影响 < 8.0，我们可以用低交互蜜罐模拟；否则用高交互。
        if selected['impact_score'] < 8.0:
            selected['resource_req'] = 'Low-Interaction'
            selected['deploy_cost'] = 1  # 假设消耗 1 单位资源
        else:
            selected['resource_req'] = 'High-Interaction'
            selected['deploy_cost'] = 5  # 假设消耗 5 单位资源
            
        return selected

# 测试一下
if __name__ == "__main__":
    loader = CVEDataLoader("processed_cve_pool.json") # 确保文件名对应
    print(loader.get_random_vuln(min_score=9.0))