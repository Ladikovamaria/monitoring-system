# src/collector_app/collector_loop.py
from __future__ import annotations

import json
import os
import time
from typing import Optional, List, Dict, Any

import requests

from src.collector_app.feature_builder import build_feature_rows_for_pcap
from src.collector_app.snmp_poller import SnmpSnapshot


def _list_pcaps_sorted(captures_dir: str) -> List[str]:
    files = [
        os.path.join(captures_dir, f)
        for f in os.listdir(captures_dir)
        if f.endswith(".pcap")
    ]
    files.sort(key=lambda p: os.path.getmtime(p))
    return files


def _wait_until_file_is_stable(path: str, checks: int = 3, delay_sec: float = 0.2) -> None:
    """
    Ждём, пока размер файла перестанет меняться.
    Это нужно, чтобы не начать читать файл, который tcpdump ещё пишет.
    """
    last_size = -1
    stable_count = 0

    while stable_count < checks:
        try:
            size = os.path.getsize(path)
        except FileNotFoundError:
            time.sleep(delay_sec)
            continue

        if size == last_size:
            stable_count += 1
        else:
            stable_count = 0
            last_size = size

        time.sleep(delay_sec)


def _wait_for_next_pcap(captures_dir: str, last_seen: Optional[str], poll_sec: float = 0.5) -> str:
    while True:
        pcaps = _list_pcaps_sorted(captures_dir)
        if pcaps:
            newest = pcaps[-1]
            if newest != last_seen:
                _wait_until_file_is_stable(newest)
                return newest
        time.sleep(poll_sec)


def _append_jsonl(path: str, rows: List[Dict[str, Any]]) -> None:
    with open(path, "a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row, ensure_ascii=False) + "\n")


def run_collector(
    *,
    captures_dir: str,
    dt_sec: float,
    snmp_host: str,
    snmp_community: str,
    if_index: int,
    cpu_oid: Optional[str] = None,
    backend_url: Optional[str] = None,
    jsonl_path: Optional[str] = None,
) -> None:
    """
    Главный цикл collector.

    Логика:
    1. ждём новый pcap-файл
    2. считаем метрики по VLAN
    3. делаем SNMP snapshot/rates
    4. сохраняем строки или отправляем на backend
    """
    last_pcap: Optional[str] = None
    prev_snmp: Optional[SnmpSnapshot] = None

    print("[collector] started")
    print(f"[collector] captures_dir={captures_dir}")
    print(f"[collector] snmp_host={snmp_host}, if_index={if_index}")

    while True:
        try:
            pcap_path = _wait_for_next_pcap(captures_dir, last_seen=last_pcap)
            last_pcap = pcap_path

            rows, prev_snmp_new = build_feature_rows_for_pcap(
                pcap_path,
                default_dt_sec=dt_sec,
                snmp_host=snmp_host,
                snmp_community=snmp_community,
                if_index=if_index,
                prev_snmp=prev_snmp,
                cpu_oid=cpu_oid,
            )

            prev_snmp = prev_snmp_new

            if not rows:
                print(f"[collector] skip first window or empty result: {os.path.basename(pcap_path)}")
                continue

            if jsonl_path:
                _append_jsonl(jsonl_path, rows)

            if backend_url:
                try:
                    response = requests.post(backend_url, json=rows, timeout=5)
                    response.raise_for_status()
                except Exception as exc:
                    print(f"[collector] backend POST failed: {exc}")

            print(f"[collector] processed {os.path.basename(pcap_path)} -> {len(rows)} row(s)")
            for row in rows:
                print(row)

        except KeyboardInterrupt:
            print("[collector] stopped by user")
            break
        except Exception as exc:
            print(f"[collector] error: {exc}")
            time.sleep(1.0)