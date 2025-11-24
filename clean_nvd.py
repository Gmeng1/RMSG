#!/usr/bin/env python3
"""
clean_nvd.py

读取 NVD 2025 CVE JSON 数据，筛选高危网络漏洞并导出为 processed_cve_pool.json。

筛选条件：
1. 仅保留 attackVector == 'NETWORK'
2. baseScore >= 7.0
3. 缺失 CVSS v3 数据的条目直接跳过

输出字段：
- cve_id: 漏洞编号
- impact_score: CVSS v3 baseScore（Stackelberg 模型中的节点价值 V）
- exploit_prob: exploitabilityScore / 10.0（攻击成功概率 P，归一化到 0-1）
- desc: 英文描述
- resource_req: 若 attackComplexity == 'LOW' 记为 'High-Interaction'，否则记为 'Low-Interaction'
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Clean NVD CVE dataset for Stackelberg honeypot experiments."
    )
    parser.add_argument(
        "--input",
        default="dataSet/nvdcve-2.0-2025.json",
        help="路径指向 NVD JSON 文件，默认使用项目内数据集。",
    )
    parser.add_argument(
        "--output",
        default="processed_cve_pool.json",
        help="清洗结果输出路径（JSON）。默认写入当前工作目录。",
    )
    return parser.parse_args()


def load_json(path: Path) -> Dict[str, Any]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def normalize_exploitability(score: float) -> float:
    # NVD v3 exploitabilityScore 范围 0-10，直接缩放到 0-1
    return round(score / 10.0, 4)


def map_resource_requirement(attack_complexity: str) -> str:
    if attack_complexity == "LOW":
        return "High-Interaction"
    return "Low-Interaction"


def _extract_from_legacy_item(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    兼容旧版 NVD JSON（nvdcve-1.1-x.json）结构：
    顶层键为 CVE_Items，内部使用 impact.baseMetricV3.cvssV3。
    """
    try:
        cve_id = entry["cve"]["CVE_data_meta"]["ID"]
        description = entry["cve"]["description"]["description_data"][0]["value"]
        impact = entry["impact"]["baseMetricV3"]["cvssV3"]
        metrics_v3 = entry["impact"]["baseMetricV3"]
    except (KeyError, IndexError, TypeError):
        return None

    attack_vector = impact.get("attackVector")
    base_score = impact.get("baseScore")

    if attack_vector != "NETWORK":
        return None
    if not isinstance(base_score, (int, float)) or base_score < 7.0:
        return None

    exploit_score = metrics_v3.get("exploitabilityScore")
    attack_complexity = impact.get("attackComplexity")

    if exploit_score is None or attack_complexity is None:
        return None

    return {
        "cve_id": cve_id,
        "impact_score": base_score,
        "exploit_prob": normalize_exploitability(exploit_score),
        "desc": description,
        "resource_req": map_resource_requirement(attack_complexity),
    }


def _extract_from_v2_item(entry: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    兼容 NVD 2.0 JSON（nvdcve-2.0-2025.json）结构：
    顶层键为 vulnerabilities，内部使用 cve.metrics.cvssMetricV31[].cvssData。
    """
    try:
        cve = entry["cve"]
        cve_id = cve["id"]

        # 选取英文描述，如不存在则选第一条
        desc_list: Sequence[Dict[str, Any]] = cve.get("descriptions", [])
        description = ""
        for d in desc_list:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and desc_list:
            description = desc_list[0].get("value", "")

        metrics = cve.get("metrics", {})
        v31_list: Sequence[Dict[str, Any]] = metrics.get("cvssMetricV31", [])
        if not v31_list:
            return None

        metric = v31_list[0]
        cvss_data = metric.get("cvssData", {})

        attack_vector = cvss_data.get("attackVector")
        base_score = cvss_data.get("baseScore")
        attack_complexity = cvss_data.get("attackComplexity")
        exploit_score = metric.get("exploitabilityScore")
    except (KeyError, IndexError, TypeError):
        return None

    if attack_vector != "NETWORK":
        return None
    if not isinstance(base_score, (int, float)) or base_score < 7.0:
        return None
    if exploit_score is None or attack_complexity is None:
        return None

    return {
        "cve_id": cve_id,
        "impact_score": base_score,
        "exploit_prob": normalize_exploitability(exploit_score),
        "desc": description,
        "resource_req": map_resource_requirement(attack_complexity),
    }


def collect_records(items: List[Dict[str, Any]], is_v2_format: bool) -> List[Dict[str, Any]]:
    records: List[Dict[str, Any]] = []

    for entry in items:
        if is_v2_format:
            record = _extract_from_v2_item(entry)
        else:
            record = _extract_from_legacy_item(entry)
        if record is not None:
            records.append(record)

    return records


def main() -> None:
    args = parse_args()
    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input JSON not found: {input_path}")

    data = load_json(input_path)

    # 自动判断是旧版结构还是 NVD 2.0 结构
    if "vulnerabilities" in data:
        items = data.get("vulnerabilities", [])
        is_v2_format = True
    else:
        items = data.get("CVE_Items", [])
        is_v2_format = False

    cleaned_records = collect_records(items, is_v2_format=is_v2_format)

    with output_path.open("w", encoding="utf-8") as f:
        json.dump(cleaned_records, f, indent=2, ensure_ascii=False)

    print(
        f"Processed {len(cleaned_records)} CVE entries "
        f"→ {output_path.resolve()}"
    )


if __name__ == "__main__":
    main()

