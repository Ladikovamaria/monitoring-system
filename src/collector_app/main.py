# src/collector_app/main.py
from src.collector_app.collector_loop import run_collector


if __name__ == "__main__":
    run_collector(
        captures_dir="/var/captures",
        dt_sec=10.0,
        snmp_host="10.10.20.1",
        snmp_community="public",
        if_index=7,
        cpu_oid=None,
        backend_url=None,  # позже можно поставить URL backend
        jsonl_path="/var/captures/features.jsonl",
    )