#!/usr/bin/env python3
"""
generate_kill_chain_matrix_v2.py

改进点：
1. Log-Scaling: 使用对数计数缓解 CIC-IDS-2018 中 DoS 流量过大导致的概率失衡。
2. Benign Loop: 允许 Benign -> Benign 和 PortScan -> Benign，模拟攻击间歇期。
3. Epsilon Smoothing: 防止某些路径因数据缺失而完全为 0。
"""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
from typing import Dict, List

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

# 目标状态名称（顺序固定）
STATE_ORDER: List[str] = [
    "Benign",
    "PortScan",
    "BruteForce",
    "WebAttack",
    "DoS",
    "Botnet",
]

# 原始 Label -> 目标状态 映射
LABEL_TO_STATE: Dict[str, str] = {
    "Benign": "Benign",
    "PortScan": "PortScan",
    "FTP-Patator": "BruteForce",
    "SSH-Patator": "BruteForce",
    "Web Attack - Brute Force": "WebAttack",
    "Web Attack - Sql Injection": "WebAttack",
    "Web Attack - XSS": "WebAttack",
    "Brute Force - Web": "WebAttack",
    "Brute Force - XSS": "WebAttack",
    "SQL Injection": "WebAttack",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS Slowhttptest": "DoS",
    "DoS slowloris": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DoS",
    "Bot": "Botnet",
    "Infiltration": "WebAttack", # 将内网渗透暂时归类为 Web/Exploit 阶段
}

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--data_dir", default="dataSet/CIC-IDS-2018")
    parser.add_argument("--output_csv", default="final_transition_matrix.csv")
    parser.add_argument("--output_fig", default="final_transition_matrix.png")
    parser.add_argument("--sample_rows", type=int, default=None)
    parser.add_argument("--chunksize", type=int, default=100_000)
    # 新增：是否使用对数平滑
    parser.add_argument("--use_log_scale", action="store_true", default=True, 
                        help="使用 log(count+1) 代替原始计数，防止 DoS 淹没其他攻击。")
    return parser.parse_args()

def map_label(label: str) -> str:
    return LABEL_TO_STATE.get(label, "Benign")

def count_states_in_csv(csv_path: Path, chunksize: int, sample_rows: int | None) -> Counter:
    counts = Counter()
    rows_left = sample_rows
    for chunk in pd.read_csv(csv_path, usecols=["Label"], chunksize=chunksize):
        if rows_left is not None:
            if rows_left <= 0: break
            if len(chunk) > rows_left: chunk = chunk.iloc[:rows_left]
            rows_left -= len(chunk)
        for label, c in chunk["Label"].value_counts().items():
            counts[map_label(label)] += int(c)
    return counts

def count_states_in_dir(data_dir: Path, chunksize: int, sample_rows: int | None) -> Counter:
    total_counts = Counter()
    csv_files = sorted(p for p in data_dir.iterdir() if p.suffix.lower() == ".csv")
    if not csv_files: raise FileNotFoundError(f"No CSV files in {data_dir}")
    
    print("Counting state frequencies...")
    for csv in csv_files:
        # print(f"  Processing {csv.name}...") # 减少刷屏
        total_counts.update(count_states_in_csv(csv, chunksize, sample_rows))
    return total_counts

def get_weighted_probs(targets: List[str], counts: Dict[str, int], use_log: bool = True) -> List[float]:
    """
    改进版：引入 '混合均匀分布' (Mixing Uniform Distribution) 
    防止某些类别的概率因数据极度不平衡而接近于 0。
    """
    # 1. 获取原始数据权重
    raw_vals = [counts.get(t, 0) for t in targets]
    eps = 1e-6
    
    if use_log:
        weights = [np.log1p(v) + eps for v in raw_vals]
    else:
        weights = [v + eps for v in raw_vals]
    
    total_w = sum(weights)
    if total_w == 0:
        data_probs = [1.0 / len(targets)] * len(targets) # 均分
    else:
        data_probs = [w / total_w for w in weights]

    # 2. 强制混合均匀分布 (关键修正步骤!)
    # mix_ratio 控制“数据真实性”和“实验不确定性”的平衡。
    # 0.7 表示 70% 尊重数据，30% 强行平均。
    mix_ratio = 0.7 
    uniform_prob = 1.0 / len(targets)
    
    final_probs = []
    for p in data_probs:
        # 混合公式： P_final = alpha * P_data + (1-alpha) * P_uniform
        new_p = (mix_ratio * p) + ((1 - mix_ratio) * uniform_prob)
        final_probs.append(new_p)

    # 再次归一化以防万一
    final_total = sum(final_probs)
    return [fp / final_total for fp in final_probs]
    """
    辅助函数：计算一组目标状态的相对概率权重
    """
    eps = 1e-6 # 平滑因子
    raw_vals = [counts.get(t, 0) for t in targets]
    
    if use_log:
        # 使用 log(x+1) 压缩数值范围
        weights = [np.log1p(v) + eps for v in raw_vals]
    else:
        weights = [v + eps for v in raw_vals]
        
    total = sum(weights)
    return [w / total for w in weights]

def build_transition_matrix_from_counts(counts: Counter, use_log: bool) -> pd.DataFrame:
    state_counts = {s: counts.get(s, 0) for s in STATE_ORDER}
    print("\n=== State Counts (Processed) ===")
    for s, c in state_counts.items():
        print(f"{s:12s}: {c}")

    n = len(STATE_ORDER)
    mat = np.zeros((n, n), dtype=float)
    idx = {s: i for i, s in enumerate(STATE_ORDER)}

    # === 逻辑掩码与概率填充 ===

    # 1. Benign
    #    - 80% 保持 Benign (和平时期)
    #    - 20% 转 PortScan (攻击开始)
    mat[idx["Benign"], idx["Benign"]] = 0.8
    mat[idx["Benign"], idx["PortScan"]] = 0.2

    # 2. PortScan (侦查阶段)
    #    - 10% 放弃/失败 -> Benign
    #    - 90% 进攻 -> BruteForce 或 WebAttack (按数据分布)
    probs_attack = get_weighted_probs(["BruteForce", "WebAttack"], state_counts, use_log)
    attack_prob_total = 0.9
    
    mat[idx["PortScan"], idx["Benign"]] = 0.1
    mat[idx["PortScan"], idx["BruteForce"]] = probs_attack[0] * attack_prob_total
    mat[idx["PortScan"], idx["WebAttack"]] = probs_attack[1] * attack_prob_total

    # 3. BruteForce (入侵阶段 A)
    #    - 转移到 DoS 或 Botnet (按数据分布)
    probs_next = get_weighted_probs(["DoS", "Botnet"], state_counts, use_log)
    mat[idx["BruteForce"], idx["DoS"]] = probs_next[0]
    mat[idx["BruteForce"], idx["Botnet"]] = probs_next[1]

    # 4. WebAttack (入侵阶段 B)
    #    - 同样转移到 DoS 或 Botnet
    #    - 这里可以微调，比如 WebAttack 更容易导致 Botnet (僵尸网络注入) 而非 DoS
    #    - 但为了保持客观，暂用数据分布
    probs_next_web = get_weighted_probs(["DoS", "Botnet"], state_counts, use_log)
    mat[idx["WebAttack"], idx["DoS"]] = probs_next_web[0]
    mat[idx["WebAttack"], idx["Botnet"]] = probs_next_web[1]

    # 5. DoS / Botnet (终态)
    #    - 90% 自循环 (持续攻击)
    #    - 10% 停止 (回到 Benign)
    mat[idx["DoS"], idx["DoS"]] = 0.9
    mat[idx["DoS"], idx["Benign"]] = 0.1
    
    mat[idx["Botnet"], idx["Botnet"]] = 0.9
    mat[idx["Botnet"], idx["Benign"]] = 0.1

    # === 归一化与校验 ===
    row_sums = mat.sum(axis=1, keepdims=True)
    # 避免除以0（虽然上面逻辑保证了不会全0）
    mat = np.divide(mat, row_sums, where=row_sums!=0)
    
    df = pd.DataFrame(mat, index=STATE_ORDER, columns=STATE_ORDER)
    return df

def plot_heatmap(mat: pd.DataFrame, output_fig: Path) -> None:
    plt.figure(figsize=(8, 6))
    sns.heatmap(mat, annot=True, fmt=".2f", cmap="YlGnBu", cbar=True)
    plt.title("Kill Chain MDP Matrix (Log-Scaled)")
    plt.tight_layout()
    plt.savefig(output_fig, dpi=200)
    print(f"Heatmap saved to {output_fig}")

def main() -> None:
    args = parse_args()
    data_dir = Path(args.data_dir)
    if not data_dir.exists(): raise FileNotFoundError(f"Not found: {data_dir}")

    counts = count_states_in_dir(data_dir, args.chunksize, args.sample_rows)
    
    # 传入 use_log_scale 参数
    mat = build_transition_matrix_from_counts(counts, args.use_log_scale)
    
    mat.to_csv(args.output_csv)
    print(f"\nMatrix saved to {args.output_csv}")
    print(mat)
    plot_heatmap(mat, Path(args.output_fig))

if __name__ == "__main__":
    main()