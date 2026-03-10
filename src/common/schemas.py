# src/common/schemas.py
from datetime import datetime
from typing import Optional

from pydantic import BaseModel


class FeatureRow(BaseModel):
    timestamp: datetime
    vlan_id: int

    bytes_per_sec: float
    frames_per_sec: float
    broadcast_ratio: float
    arp_per_sec: float
    active_ip_count: int
    active_flow_count: int
    iat_mean: float
    iat_std: float

    snmp_in_errors_rate: float
    snmp_out_errors_rate: float
    snmp_discards_rate: float
    snmp_cpu: Optional[float] = None
    if_oper_status: int

    pcap_file: Optional[str] = None