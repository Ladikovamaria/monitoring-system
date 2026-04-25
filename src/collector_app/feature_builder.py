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
    snmp_hosts: List[str],
    snmp_community: str,
    prev_snmp_by_device: Dict[str, Dict[int, SnmpSnapshot]],
    cpu_oid: Optional[str] = None,
) -> tuple[
    List[Dict[str, Any]],
    Dict[str, Dict[int, SnmpSnapshot]],
    List[Dict[str, Any]],
]:
    vlan_rows = compute_features_per_vlan_from_pcap(
        pcap_path,
        default_dt_sec=default_dt_sec,
        include_untagged=True,
    )

    timestamp = datetime.now(tz=timezone.utc)

    new_prev_snmp_by_device: Dict[str, Dict[int, SnmpSnapshot]] = {}
    interface_status_rows: List[Dict[str, Any]] = []
    all_rates_by_device: Dict[str, Dict[int, Dict[str, Any]]] = {}

    for snmp_host in snmp_hosts:
        try:
            snmp_curr_list = poll_all_snmp_snapshots(
                host=snmp_host,
                community=snmp_community,
                cpu_oid=cpu_oid,
                use_high_capacity=True,
                timeout=1,
                retries=2,
            )
        except Exception as exc:
            print(f"[SNMP] host {snmp_host} polling failed: {exc}")
            continue

        snmp_curr_by_if_index: Dict[int, SnmpSnapshot] = {
            snapshot.if_index: snapshot
            for snapshot in snmp_curr_list
        }

        new_prev_snmp_by_device[snmp_host] = snmp_curr_by_if_index

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

        prev_for_host = prev_snmp_by_device.get(snmp_host, {})
        rates_by_if_index: Dict[int, Dict[str, Any]] = {}

        for if_index, curr_snapshot in snmp_curr_by_if_index.items():
            prev_snapshot = prev_for_host.get(if_index)

            if prev_snapshot is None:
                continue

            if curr_snapshot.if_oper_status is None:
                print(
                    f"[SNMP] skip rates: ifOperStatus is None "
                    f"host={snmp_host}, if_index={if_index}, if_name={curr_snapshot.if_name}"
                )
                continue

            rates = compute_snmp_rates(
                prev_snapshot,
                curr_snapshot,
                dt_sec=default_dt_sec,
            )

            rates_by_if_index[if_index] = asdict(rates)

        all_rates_by_device[snmp_host] = rates_by_if_index

    if not prev_snmp_by_device:
        return [], new_prev_snmp_by_device, interface_status_rows

    out: List[Dict[str, Any]] = []

    # Для ML/features используем SNMP-метрики первого устройства из списка.
    # Статусы интерфейсов всех устройств всё равно пишутся в interface_status.
    if not snmp_hosts:
        return [], new_prev_snmp_by_device, interface_status_rows

    main_snmp_host = snmp_hosts[0]
    main_rates_by_if_index = all_rates_by_device.get(main_snmp_host, {})

    for vf in vlan_rows:
        for _if_index, snmp_rates in main_rates_by_if_index.items():
            row = {
                "timestamp": datetime.fromtimestamp(
                    vf.timestamp_end,
                    tz=timezone.utc,
                ),

                "vlan_id": vf.vlan_id if vf.vlan_id is not None else 0,

                "bytes_per_sec": vf.bytes_per_sec,
                "frames_per_sec": vf.frames_per_sec,
                "broadcast_ratio": vf.broadcast_ratio,
                "arp_per_sec": vf.arp_per_sec,
                "active_ip_count": vf.active_ip_count,
                "active_flow_count": vf.active_flow_count,
                "iat_mean": vf.iat_mean,
                "iat_std": vf.iat_std,

                **snmp_rates,

                "pcap_file": pcap_path.split("/")[-1],
            }

            out.append(row)

    return out, new_prev_snmp_by_device, interface_status_rows