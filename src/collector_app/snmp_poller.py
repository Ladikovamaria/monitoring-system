# src/collector_app/snmp_poller.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi import (
    getCmd,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)

@dataclass(frozen=True)
class SnmpSnapshot:
    """
    Сырые накопительные SNMP счётчики + статус интерфейса + CPU (если есть).
    """
    if_oper_status: int
    in_octets: int
    out_octets: int
    in_errors: int
    out_errors: int
    in_discards: int
    out_discards: int
    cpu: Optional[int]


@dataclass(frozen=True)
class SnmpRates:
    """
    Производные SNMP-метрики за интервал времени.
    """
    snmp_in_errors_rate: float
    snmp_out_errors_rate: float
    snmp_discards_rate: float
    if_oper_status: int
    snmp_cpu: Optional[int]


def _to_python(val: Any) -> Any:
    try:
        return int(val)
    except Exception:
        return val.prettyPrint()


def snmp_get_many_named(
    host: str,
    community: str,
    name_to_oid: dict[str, str],
    timeout: int = 1,
    retries: int = 2,
) -> dict[str, Any]:
    names = list(name_to_oid.keys())
    oids = [name_to_oid[n] for n in names]
    objects = [ObjectType(ObjectIdentity(oid)) for oid in oids]

    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),  # SNMP v2c
        UdpTransportTarget((host, 161), timeout=timeout, retries=retries),
        ContextData(),
        *objects,
    )

    error_indication, error_status, error_index, var_binds = next(iterator)

    if error_indication:
        raise RuntimeError(f"SNMP transport error: {error_indication}")
    if error_status:
        bad_i = int(error_index) - 1
        bad_name = names[bad_i] if 0 <= bad_i < len(names) else "unknown"
        raise RuntimeError(
            f"SNMP agent error: {error_status.prettyPrint()} "
            f"(field={bad_name}, index={int(error_index)})"
        )

    out: dict[str, Any] = {}
    for name, (_oid, val) in zip(names, var_binds):
        out[name] = _to_python(val)

    return out


def _need_int(vals: dict[str, Any], key: str) -> int:
    v = vals.get(key)
    if isinstance(v, int):
        return v
    raise RuntimeError(f"Bad SNMP value for {key}: {v!r}")


def _get_optional_int(vals: dict[str, Any], key: str) -> Optional[int]:
    v = vals.get(key)
    return v if isinstance(v, int) else None


def _safe_delta(curr: int, prev: int) -> int:
    """
    Защита от сброса счётчиков/перезагрузки интерфейса.
    """
    d = curr - prev
    return d if d >= 0 else 0


def poll_snmp_snapshot(
    host: str,
    community: str,
    if_index: int,
    *,
    use_high_capacity: bool = True,
    cpu_oid: Optional[str] = None,
    timeout: int = 1,
    retries: int = 2,
) -> SnmpSnapshot:
    """
    Получает SNMP snapshot для одного интерфейса.
    """
    name_to_oid: dict[str, str] = {
        "ifOperStatus": f"1.3.6.1.2.1.2.2.1.8.{if_index}",
        "ifInErrors": f"1.3.6.1.2.1.2.2.1.14.{if_index}",
        "ifOutErrors": f"1.3.6.1.2.1.2.2.1.20.{if_index}",
        "ifInDiscards": f"1.3.6.1.2.1.2.2.1.13.{if_index}",
        "ifOutDiscards": f"1.3.6.1.2.1.2.2.1.19.{if_index}",
    }

    if use_high_capacity:
        name_to_oid["ifInOctets"] = f"1.3.6.1.2.1.31.1.1.1.6.{if_index}"
        name_to_oid["ifOutOctets"] = f"1.3.6.1.2.1.31.1.1.1.10.{if_index}"
    else:
        name_to_oid["ifInOctets"] = f"1.3.6.1.2.1.2.2.1.10.{if_index}"
        name_to_oid["ifOutOctets"] = f"1.3.6.1.2.1.2.2.1.16.{if_index}"

    if cpu_oid:
        name_to_oid["cpu"] = cpu_oid

    vals = snmp_get_many_named(
        host, community, name_to_oid, timeout=timeout, retries=retries
    )

    return SnmpSnapshot(
        if_oper_status=_need_int(vals, "ifOperStatus"),
        in_octets=_need_int(vals, "ifInOctets"),
        out_octets=_need_int(vals, "ifOutOctets"),
        in_errors=_need_int(vals, "ifInErrors"),
        out_errors=_need_int(vals, "ifOutErrors"),
        in_discards=_need_int(vals, "ifInDiscards"),
        out_discards=_need_int(vals, "ifOutDiscards"),
        cpu=_get_optional_int(vals, "cpu"),
    )


def compute_snmp_rates(prev: SnmpSnapshot, curr: SnmpSnapshot, dt_sec: float) -> SnmpRates:
    if dt_sec <= 0:
        raise ValueError("dt_sec must be > 0")

    d_in_err = _safe_delta(curr.in_errors, prev.in_errors)
    d_out_err = _safe_delta(curr.out_errors, prev.out_errors)
    d_in_disc = _safe_delta(curr.in_discards, prev.in_discards)
    d_out_disc = _safe_delta(curr.out_discards, prev.out_discards)

    return SnmpRates(
        snmp_in_errors_rate=float(d_in_err / dt_sec),
        snmp_out_errors_rate=float(d_out_err / dt_sec),
        snmp_discards_rate=float((d_in_disc + d_out_disc) / dt_sec),
        if_oper_status=int(curr.if_oper_status),
        snmp_cpu=curr.cpu,
    )