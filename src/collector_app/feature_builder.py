# src/collector_app/feature_builder.py
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from src.collector_app.pcap_extractor import compute_features_per_vlan_from_pcap
from src.collector_app.snmp_poller import (
    poll_snmp_snapshot,
    compute_snmp_rates,
    SnmpSnapshot,
)


def build_feature_rows_for_pcap(
    pcap_path: str,
    *,
    default_dt_sec: float,
    snmp_host: str,
    snmp_community: str,
    if_index: int,
    prev_snmp: Optional[SnmpSnapshot],
    cpu_oid: Optional[str] = None,
) -> tuple[List[Dict[str, Any]], Optional[SnmpSnapshot]]:
    """
    Возвращает:
    - список строк признаков (по одной на VLAN)
    - текущий SNMP snapshot, который нужно сохранить для следующего окна
    """
    vlan_rows = compute_features_per_vlan_from_pcap(
        pcap_path,
        default_dt_sec=default_dt_sec,
        include_untagged=False,
    )

    snmp_curr = poll_snmp_snapshot(
        host=snmp_host,
        community=snmp_community,
        if_index=if_index,
        cpu_oid=cpu_oid,
        use_high_capacity=True,
        timeout=1,
        retries=2,
    )

    if prev_snmp is None:
        return ([], snmp_curr)

    snmp_rates = compute_snmp_rates(prev_snmp, snmp_curr, dt_sec=default_dt_sec)

    out: List[Dict[str, Any]] = []
    for vf in vlan_rows:
        row = {
            "timestamp": datetime.fromtimestamp(vf.timestamp_end, tz=timezone.utc),
            "vlan_id": vf.vlan_id,

            # PCAP
            "bytes_per_sec": vf.bytes_per_sec,
            "frames_per_sec": vf.frames_per_sec,
            "broadcast_ratio": vf.broadcast_ratio,
            "arp_per_sec": vf.arp_per_sec,
            "active_ip_count": vf.active_ip_count,
            "active_flow_count": vf.active_flow_count,
            "iat_mean": vf.iat_mean,
            "iat_std": vf.iat_std,

            # SNMP
            **asdict(snmp_rates),

            # служебные поля
            "pcap_file": pcap_path.split("/")[-1],
        }
        out.append(row)

    return (out, snmp_curr)