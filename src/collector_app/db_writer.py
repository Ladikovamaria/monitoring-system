# src/collector_app/db_writer.py
from __future__ import annotations

from typing import Any, Dict, List, Optional

import psycopg2
from psycopg2.extras import execute_batch


class PostgresWriter:
    def __init__(self, dsn: str) -> None:
        self.dsn = dsn

    def insert_feature_rows(self, rows: List[Dict[str, Any]]) -> None:
        if not rows:
            return

        sql = """
        INSERT INTO features (
            timestamp,
            vlan_id,
            bytes_per_sec,
            frames_per_sec,
            broadcast_ratio,
            arp_per_sec,
            active_ip_count,
            active_flow_count,
            iat_mean,
            iat_std,
            snmp_in_errors_rate,
            snmp_out_errors_rate,
            snmp_discards_rate,
            snmp_cpu,
            if_oper_status,
            pcap_file
        ) VALUES (
            %(timestamp)s,
            %(vlan_id)s,
            %(bytes_per_sec)s,
            %(frames_per_sec)s,
            %(broadcast_ratio)s,
            %(arp_per_sec)s,
            %(active_ip_count)s,
            %(active_flow_count)s,
            %(iat_mean)s,
            %(iat_std)s,
            %(snmp_in_errors_rate)s,
            %(snmp_out_errors_rate)s,
            %(snmp_discards_rate)s,
            %(snmp_cpu)s,
            %(if_oper_status)s,
            %(pcap_file)s
        )
        """

        conn = psycopg2.connect(self.dsn)
        try:
            with conn:
                with conn.cursor() as cur:
                    execute_batch(cur, sql, rows, page_size=100)
        finally:
            conn.close()