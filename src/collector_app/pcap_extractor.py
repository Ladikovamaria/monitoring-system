# src/collector_app/pcap_extractor.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, Set, List
import math

from scapy.all import PcapReader, Ether, ARP, IP, TCP, UDP, Dot1Q  # type: ignore


@dataclass(frozen=True)
class VlanFeatures:
    timestamp_start: float
    timestamp_end: float
    dt_sec: float

    vlan_id: int

    # L2
    bytes_per_sec: float
    frames_per_sec: float
    broadcast_ratio: float
    arp_per_sec: float

    # L3/L4
    active_ip_count: int
    active_flow_count: int

    # Timing
    iat_mean: float
    iat_std: float


class _Agg:
    """
    Внутренний аккумулятор статистики для одного VLAN.
    """
    __slots__ = (
        "first_ts",
        "last_ts",
        "total_bytes",
        "total_frames",
        "broadcast_frames",
        "arp_frames",
        "unique_ips",
        "unique_flows",
        "prev_ts",
        "iats",
    )

    def __init__(self) -> None:
        self.first_ts: Optional[float] = None
        self.last_ts: Optional[float] = None

        self.total_bytes: int = 0
        self.total_frames: int = 0
        self.broadcast_frames: int = 0
        self.arp_frames: int = 0

        self.unique_ips: Set[str] = set()
        self.unique_flows: Set[Tuple[str, str, int, int, int]] = set()

        self.prev_ts: Optional[float] = None
        self.iats: List[float] = []


def _pkt_len_bytes(pkt) -> int:
    try:
        return len(bytes(pkt))
    except Exception:
        return 0


def _is_broadcast(pkt) -> bool:
    try:
        eth = pkt[Ether]
        return eth.dst.lower() == "ff:ff:ff:ff:ff:ff"
    except Exception:
        return False


def _extract_ip_pair(pkt) -> Optional[Tuple[str, str]]:
    if IP in pkt:
        ip = pkt[IP]
        return ip.src, ip.dst
    return None


def _extract_flow_5tuple(pkt) -> Optional[Tuple[str, str, int, int, int]]:
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = int(ip.proto)

    if TCP in pkt:
        tcp = pkt[TCP]
        return (ip.src, ip.dst, int(tcp.sport), int(tcp.dport), proto)

    if UDP in pkt:
        udp = pkt[UDP]
        return (ip.src, ip.dst, int(udp.sport), int(udp.dport), proto)

    return (ip.src, ip.dst, 0, 0, proto)


def _get_vlan_id(pkt) -> Optional[int]:
    """
    Возвращает VLAN ID из 802.1Q тега.
    Если кадр без тега, возвращает None.
    """
    if Dot1Q in pkt:
        try:
            return int(pkt[Dot1Q].vlan)
        except Exception:
            return None
    return None


def compute_features_per_vlan_from_pcap(
    pcap_path: str,
    *,
    default_dt_sec: float = 10.0,
    include_untagged: bool = False,
    untagged_vlan_id: int = 0,
) -> List[VlanFeatures]:
    """
    Читает один PCAP и возвращает список VlanFeatures — по одному объекту на VLAN.

    Логика:
    - группировка пакетов по VLAN
    - метрики считаются отдельно для каждого VLAN
    - dt для каждого VLAN берётся как фактическая длительность между первым и последним пакетом
    - если пакетов слишком мало, используется default_dt_sec
    """
    if default_dt_sec <= 0:
        raise ValueError("default_dt_sec must be > 0")

    aggs: Dict[int, _Agg] = {}

    with PcapReader(pcap_path) as pr:
        for pkt in pr:
            try:
                ts = float(pkt.time)
            except Exception:
                continue

            vlan = _get_vlan_id(pkt)
            if vlan is None:
                if not include_untagged:
                    continue
                vlan = untagged_vlan_id

            agg = aggs.get(vlan)
            if agg is None:
                agg = _Agg()
                aggs[vlan] = agg

            if agg.first_ts is None:
                agg.first_ts = ts
            agg.last_ts = ts

            agg.total_frames += 1
            agg.total_bytes += _pkt_len_bytes(pkt)

            if _is_broadcast(pkt):
                agg.broadcast_frames += 1

            if ARP in pkt:
                agg.arp_frames += 1

            ip_pair = _extract_ip_pair(pkt)
            if ip_pair:
                agg.unique_ips.add(ip_pair[0])
                agg.unique_ips.add(ip_pair[1])

            flow = _extract_flow_5tuple(pkt)
            if flow:
                agg.unique_flows.add(flow)

            if agg.prev_ts is not None:
                dt = ts - agg.prev_ts
                if dt >= 0:
                    agg.iats.append(dt)
            agg.prev_ts = ts

    out: List[VlanFeatures] = []

    for vlan_id, agg in sorted(aggs.items(), key=lambda x: x[0]):
        if agg.first_ts is None or agg.last_ts is None:
            ts_start = 0.0
            ts_end = 0.0
            dt_sec = default_dt_sec
        else:
            ts_start = agg.first_ts
            ts_end = agg.last_ts
            dt_sec = ts_end - ts_start
            if dt_sec < 1e-6:
                dt_sec = default_dt_sec

        bytes_per_sec = agg.total_bytes / dt_sec
        frames_per_sec = agg.total_frames / dt_sec
        arp_per_sec = agg.arp_frames / dt_sec
        broadcast_ratio = (
            agg.broadcast_frames / agg.total_frames if agg.total_frames > 0 else 0.0
        )

        active_ip_count = len(agg.unique_ips)
        active_flow_count = len(agg.unique_flows)

        if not agg.iats:
            iat_mean = 0.0
            iat_std = 0.0
        else:
            iat_mean = sum(agg.iats) / len(agg.iats)
            var = sum((x - iat_mean) ** 2 for x in agg.iats) / len(agg.iats)
            iat_std = math.sqrt(var)

        out.append(
            VlanFeatures(
                timestamp_start=float(ts_start),
                timestamp_end=float(ts_end),
                dt_sec=float(dt_sec),
                vlan_id=int(vlan_id),
                bytes_per_sec=float(bytes_per_sec),
                frames_per_sec=float(frames_per_sec),
                broadcast_ratio=float(broadcast_ratio),
                arp_per_sec=float(arp_per_sec),
                active_ip_count=int(active_ip_count),
                active_flow_count=int(active_flow_count),
                iat_mean=float(iat_mean),
                iat_std=float(iat_std),
            )
        )

    return out