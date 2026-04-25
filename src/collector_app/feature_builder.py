# src/collector_app/feature_builder.py
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Dict, List, Optional
from datetime import datetime, timezone

from src.collector_app.pcap_extractor import compute_features_per_vlan_from_pcap
from src.collector_app.snmp_poller import (
    poll_all_snmp_snapshots,
    compute_snmp_rates,
    SnmpSnapshot,
)


def build_feature_rows_for_pcap(
    pcap_path: str,
    *,
    default_dt_sec: float,
    snmp_host: str,
    snmp_community: str,
    prev_snmp_by_if_index: Dict[int, SnmpSnapshot],
    cpu_oid: Optional[str] = None,
) -> tuple[
    List[Dict[str, Any]],
    Dict[int, SnmpSnapshot],
    List[Dict[str, Any]],
]:
    """
    Возвращает:
    - строки признаков для таблицы features;
    - текущие SNMP snapshot по всем интерфейсам;
    - строки состояния интерфейсов для таблицы interface_status.
    """

    vlan_rows = compute_features_per_vlan_from_pcap(
        pcap_path,
        default_dt_sec=default_dt_sec,

        # ВАЖНО: теперь анализируется и трафик без VLAN.
        include_untagged=True,
    )

    snmp_curr_list = poll_all_snmp_snapshots(
        host=snmp_host,
        community=snmp_community,
        cpu_oid=cpu_oid,
        use_high_capacity=True,
        timeout=1,
        retries=2,
    )

    snmp_curr_by_if_index: Dict[int, SnmpSnapshot] = {
        snapshot.if_index: snapshot
        for snapshot in snmp_curr_list
    }

    timestamp = datetime.now(tz=timezone.utc)

    interface_status_rows: List[Dict[str, Any]] = []

    for snapshot in snmp_curr_list:
        interface_status_rows.append(
            {
                "timestamp": timestamp,
                "snmp_host": snmp_host,
                "if_index": snapshot.if_index,
                "if_name": snapshot.if_name,
                "if_descr": snapshot.if_descr,
                "if_admin_status": snapshot.if_admin_status,
                "if_oper_status": snapshot.if_oper_status,
                "is_up": snapshot.if_oper_status == 1,
            }
        )

    # Первое окно нужно только для сохранения стартовых SNMP-счётчиков.
    if not prev_snmp_by_if_index:
        return [], snmp_curr_by_if_index, interface_status_rows

    snmp_rates_by_if_index: Dict[int, Dict[str, Any]] = {}

    for if_index, curr_snapshot in snmp_curr_by_if_index.items():
        prev_snapshot = prev_snmp_by_if_index.get(if_index)

        if prev_snapshot is None:
            continue

        rates = compute_snmp_rates(
            prev_snapshot,
            curr_snapshot,
            dt_sec=default_dt_sec,
        )

        snmp_rates_by_if_index[if_index] = asdict(rates)

    out: List[Dict[str, Any]] = []

    for vf in vlan_rows:
        for if_index, snmp_rates in snmp_rates_by_if_index.items():
            row = {
                "timestamp": datetime.fromtimestamp(
                    vf.timestamp_end,
                    tz=timezone.utc,
                ),

                # VLAN
                # Для трафика без VLAN здесь будет None.
                "vlan_id": vf.vlan_id if vf.vlan_id is not None else 0,

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
                **snmp_rates,

                # служебные поля
                "snmp_host": snmp_host,
                "pcap_file": pcap_path.split("/")[-1],
            }

            out.append(row)

    return out, snmp_curr_by_if_index, interface_status_rows