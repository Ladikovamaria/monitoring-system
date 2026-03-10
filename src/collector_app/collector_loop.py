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


def _wait_for_next_completed_pcap(
    captures_dir: str,
    processed_files: set[str],
    poll_sec: float = 0.5,
) -> str:
    """
    Ждёт новый завершённый pcap-файл.

    Последний файл считаем текущим (tcpdump ещё пишет в него),
    поэтому обрабатываем предпоследний.
    """
    while True:
        pcaps = _list_pcaps_sorted(captures_dir)

        if len(pcaps) >= 2:
            completed = pcaps[-2]

            if completed not in processed_files:
                try:
                    size = os.path.getsize(completed)
                except FileNotFoundError:
                    time.sleep(poll_sec)
                    continue

                # 24 байта — это только pcap header, полезно иметь больше
                if size > 24:
                    return completed

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
    processed_files: set[str] = set()
    prev_snmp: Optional[SnmpSnapshot] = None

    print("[collector] started")
    print(f"[collector] captures_dir={captures_dir}")
    print(f"[collector] snmp_host={snmp_host}, if_index={if_index}")

    while True:
        try:
            pcap_path = _wait_for_next_completed_pcap(
                captures_dir=captures_dir,
                processed_files=processed_files,
            )

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
            processed_files.add(pcap_path)

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