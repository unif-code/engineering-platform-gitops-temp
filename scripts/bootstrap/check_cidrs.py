#!/usr/bin/env python3
"""检查目标 Service/Pod CIDR 与服务器本地 IPv4 范围是否重叠。"""

from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import re
import sys
from typing import Sequence


class ArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> None:
        raise ValueError(message)


def parser() -> ArgumentParser:
    result = ArgumentParser(add_help=True)
    result.add_argument('--service-cidr', required=True)
    result.add_argument('--pod-cidr', required=True)
    result.add_argument('--address', action='append', default=[])
    result.add_argument('--route', action='append', default=[])
    # 已安装 CNI 自己在宿主机上建立的网卡：仅这些网卡上、且完全落在 Pod CIDR 内的
    # 地址/路由不算冲突；Service CIDR 一律不豁免。
    result.add_argument('--cni-device', action='append', default=[])
    return result


DEVICE_PATTERN = re.compile(r'^[A-Za-z0-9_.-]{1,15}$')
CNI_PATTERN = re.compile(r'^[A-Za-z0-9_.*?-]{1,15}$')


def split_device(value: str) -> tuple[str, str | None]:
    """`前缀@网卡` → (前缀, 网卡)；无 `@` 时网卡未知，永不豁免。"""
    if '@' not in value:
        return value, None
    prefix, device = value.rsplit('@', 1)
    if not DEVICE_PATTERN.match(device):
        raise ValueError(f'invalid device: {value}')
    return prefix, device


def cni_owned(device: str | None, patterns: Sequence[str]) -> bool:
    return device is not None and any(
        fnmatch.fnmatchcase(device, pattern) for pattern in patterns
    )


def network(value: str) -> ipaddress.IPv4Network:
    parsed = ipaddress.ip_network(value, strict=False)
    if not isinstance(parsed, ipaddress.IPv4Network):
        raise ValueError(f'not IPv4: {value}')
    return parsed


def address_network(value: str) -> ipaddress.IPv4Network:
    parsed = ipaddress.ip_interface(value)
    if not isinstance(parsed, ipaddress.IPv4Interface):
        raise ValueError(f'not IPv4: {value}')
    return ipaddress.ip_network(f'{parsed.ip}/32')


def stop(reason: str) -> int:
    print('RESULT=STOP_CIDR_OVERLAP')
    print(f'REASON={reason}')
    return 10


def main(arguments: Sequence[str] | None = None) -> int:
    try:
        options = parser().parse_args(arguments)
        service = network(options.service_cidr)
        pod = network(options.pod_cidr)
        for pattern in options.cni_device:
            if not CNI_PATTERN.match(pattern):
                raise ValueError(f'invalid cni device pattern: {pattern}')
        addresses = []
        for value in options.address:
            prefix, device = split_device(value)
            addresses.append((address_network(prefix), device))
        routes = []
        for value in options.route:
            prefix, device = split_device(value)
            routes.append((network(prefix), device))
    except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as error:
        print('RESULT=STOP_CIDR_INVALID')
        print(f'REASON={error}')
        return 10

    def pod_conflict(local: ipaddress.IPv4Network, device: str | None) -> bool:
        if not pod.overlaps(local):
            return False
        return not (cni_owned(device, options.cni_device) and local.subnet_of(pod))

    if service.overlaps(pod):
        return stop('service-and-pod-overlap')
    for local, device in addresses:
        if service.overlaps(local):
            return stop('service-overlaps-local-address')
        if pod_conflict(local, device):
            return stop('pod-overlaps-local-address')
    for local, device in routes:
        if service.overlaps(local):
            return stop('service-overlaps-local-route')
        if pod_conflict(local, device):
            return stop('pod-overlaps-local-route')

    print('RESULT=PASS_CIDRS')
    print('REASON=no-server-local-overlap')
    print('SCOPE=SERVER_LOCAL_SCOPE_ONLY')
    return 0


if __name__ == '__main__':
    sys.exit(main())
