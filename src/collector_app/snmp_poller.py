# src/collector_app/snmp_poller.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from pysnmp.entity.engine import SnmpEngine
from pysnmp.hlapi import (
    getCmd,
    nextCmd,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)


@dataclass(frozen=True)
class InterfaceInfo:
    if_index: int
    if_name: str
    if_descr: str
    if_admin_status: Optional[int]
    if_oper_status: Optional[int]


@dataclass(frozen=True)
class SnmpSnapshot:
    if_index: int
    if_name: Optional[str]
    if_descr: Optional[str]

    if_admin_status: Optional[int]
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
    if_index: int
    if_name: Optional[str]
    if_descr: Optional[str]

    snmp_in_errors_rate: float
    snmp_out_errors_rate: float
    snmp_discards_rate: float

    if_admin_status: Optional[int]
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
    objects = [ObjectType(ObjectIdentity(name_to_oid[n])) for n in names]

    iterator = getCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
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

    return {
        name: _to_python(val)
        for name, (_oid, val) in zip(names, var_binds)
    }


def snmp_walk(
    host: str,
    community: str,
    base_oid: str,
    timeout: int = 1,
    retries: int = 2,
) -> dict[int, Any]:
    result: dict[int, Any] = {}

    iterator = nextCmd(
        SnmpEngine(),
        CommunityData(community, mpModel=1),
        UdpTransportTarget((host, 161), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ObjectIdentity(base_oid)),
        lexicographicMode=False,
    )

    for error_indication, error_status, error_index, var_binds in iterator:
        if error_indication:
            raise RuntimeError(f"SNMP walk transport error: {error_indication}")

        if error_status:
            raise RuntimeError(
                f"SNMP walk agent error: {error_status.prettyPrint()} "
                f"(index={int(error_index)})"
            )

        for oid, val in var_binds:
            oid_str = oid.prettyPrint()
            if_index = int(oid_str.split(".")[-1])
            result[if_index] = _to_python(val)

    return result


def _need_int(vals: dict[str, Any], key: str) -> int:
    v = vals.get(key)
    if isinstance(v, int):
        return v
    raise RuntimeError(f"Bad SNMP value for {key}: {v!r}")


def _get_optional_int(vals: dict[str, Any], key: str) -> Optional[int]:
    v = vals.get(key)
    return v if isinstance(v, int) else None


def _safe_delta(curr: int, prev: int) -> int:
    d = curr - prev
    return d if d >= 0 else 0


def discover_interfaces(
    host: str,
    community: str,
    timeout: int = 1,
    retries: int = 2,
) -> list[InterfaceInfo]:
    """
    Получает список всех интерфейсов устройства.
    """

    if_descr = snmp_walk(
        host,
        community,
        "1.3.6.1.2.1.2.2.1.2",
        timeout=timeout,
        retries=retries,
    )

    if_admin_status = snmp_walk(
        host,
        community,
        "1.3.6.1.2.1.2.2.1.7",
        timeout=timeout,
        retries=retries,
    )

    if_oper_status = snmp_walk(
        host,
        community,
        "1.3.6.1.2.1.2.2.1.8",
        timeout=timeout,
        retries=retries,
    )

    try:
        if_name = snmp_walk(
            host,
            community,
            "1.3.6.1.2.1.31.1.1.1.1",
            timeout=timeout,
            retries=retries,
        )
    except Exception:
        if_name = {}

    interfaces: list[InterfaceInfo] = []

    for if_index in sorted(if_descr.keys()):
        interfaces.append(
            InterfaceInfo(
                if_index=if_index,
                if_name=str(if_name.get(if_index, if_descr.get(if_index, f"if{if_index}"))),
                if_descr=str(if_descr.get(if_index, f"if{if_index}")),
                if_admin_status=if_admin_status.get(if_index)
                if isinstance(if_admin_status.get(if_index), int)
                else None,
                if_oper_status=if_oper_status.get(if_index)
                if isinstance(if_oper_status.get(if_index), int)
                else None,
            )
        )

    return interfaces


def poll_snmp_snapshot(
    host: str,
    community: str,
    if_index: int,
    *,
    if_name: Optional[str] = None,
    if_descr: Optional[str] = None,
    use_high_capacity: bool = True,
    cpu_oid: Optional[str] = None,
    timeout: int = 1,
    retries: int = 2,
) -> SnmpSnapshot:
    """
    Получает SNMP snapshot для одного интерфейса.
    """

    name_to_oid: dict[str, str] = {
        "ifAdminStatus": f"1.3.6.1.2.1.2.2.1.7.{if_index}",
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
        host,
        community,
        name_to_oid,
        timeout=timeout,
        retries=retries,
    )

    return SnmpSnapshot(
        if_index=if_index,
        if_name=if_name,
        if_descr=if_descr,
        if_admin_status=_get_optional_int(vals, "ifAdminStatus"),
        if_oper_status=_need_int(vals, "ifOperStatus"),
        in_octets=_need_int(vals, "ifInOctets"),
        out_octets=_need_int(vals, "ifOutOctets"),
        in_errors=_need_int(vals, "ifInErrors"),
        out_errors=_need_int(vals, "ifOutErrors"),
        in_discards=_need_int(vals, "ifInDiscards"),
        out_discards=_need_int(vals, "ifOutDiscards"),
        cpu=_get_optional_int(vals, "cpu"),
    )


def poll_all_snmp_snapshots(
    host: str,
    community: str,
    *,
    use_high_capacity: bool = True,
    cpu_oid: Optional[str] = None,
    timeout: int = 1,
    retries: int = 2,
) -> list[SnmpSnapshot]:
    """
    Опрос всех интерфейсов устройства.
    """

    interfaces = discover_interfaces(
        host,
        community,
        timeout=timeout,
        retries=retries,
    )

    snapshots: list[SnmpSnapshot] = []

    for iface in interfaces:
        try:
            snapshot = poll_snmp_snapshot(
                host,
                community,
                iface.if_index,
                if_name=iface.if_name,
                if_descr=iface.if_descr,
                use_high_capacity=use_high_capacity,
                cpu_oid=cpu_oid,
                timeout=timeout,
                retries=retries,
            )
            snapshots.append(snapshot)
        except Exception as e:
            print(
                f"[SNMP] Не удалось опросить интерфейс "
                f"{iface.if_index} ({iface.if_name}): {e}"
            )

    return snapshots


def compute_snmp_rates(
    prev: SnmpSnapshot,
    curr: SnmpSnapshot,
    dt_sec: float,
) -> SnmpRates:
    if dt_sec <= 0:
        raise ValueError("dt_sec must be > 0")

    d_in_err = _safe_delta(curr.in_errors, prev.in_errors)
    d_out_err = _safe_delta(curr.out_errors, prev.out_errors)
    d_in_disc = _safe_delta(curr.in_discards, prev.in_discards)
    d_out_disc = _safe_delta(curr.out_discards, prev.out_discards)

    return SnmpRates(
        if_index=curr.if_index,
        if_name=curr.if_name,
        if_descr=curr.if_descr,
        snmp_in_errors_rate=float(d_in_err / dt_sec),
        snmp_out_errors_rate=float(d_out_err / dt_sec),
        snmp_discards_rate=float((d_in_disc + d_out_disc) / dt_sec),
        if_admin_status=curr.if_admin_status,
        if_oper_status=int(curr.if_oper_status),
        snmp_cpu=curr.cpu,
    )