"""Generate predictable :class:`PacketRecord` samples for tests and demos.

Nothing here performs detection and no Scapy packets are created. Every helper
returns a list of plain ``PacketRecord`` objects built from the arguments, so
callers and tests can rely on exact values. Defaults are fixed constants
(``start_time=0.0``) to keep results deterministic.
"""

from .models import PacketRecord


def tcp_packets(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=1234,
    dst_port=80,
    count=1,
    start_time=0.0,
    interval=1.0,
):
    """Normal TCP traffic between one client port and one server port."""
    return _records(
        count,
        start_time,
        interval,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="TCP",
    )


def udp_packets(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    src_port=5353,
    dst_port=53,
    count=1,
    start_time=0.0,
    interval=1.0,
):
    """Normal UDP traffic between one source and one destination port."""
    return _records(
        count,
        start_time,
        interval,
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol="UDP",
    )


def port_scan_packets(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    port_count=20,
    start_port=1,
    src_port=40000,
    start_time=0.0,
    interval=0.01,
):
    """One source contacting many different destination ports in a row."""
    records = []
    for offset in range(port_count):
        records.append(
            PacketRecord(
                timestamp=start_time + offset * interval,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=start_port + offset,
                protocol="TCP",
            )
        )
    return records


def packet_burst(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    count=100,
    src_port=1234,
    dst_port=80,
    start_time=0.0,
    interval=0.01,
):
    """A rapid burst of packets from a single source."""
    return tcp_packets(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        count=count,
        start_time=start_time,
        interval=interval,
    )


def arp_mapping_change(
    sender_ip="10.0.0.1",
    macs=("aa:bb:cc:dd:ee:ff", "11:22:33:44:55:66"),
    target_ip="10.0.0.254",
    target_mac="ff:ff:ff:ff:ff:ff",
    start_time=0.0,
    interval=1.0,
):
    """ARP replies where one IP claims different MAC addresses over time."""
    records = []
    for index, mac in enumerate(macs):
        records.append(
            PacketRecord(
                timestamp=start_time + index * interval,
                protocol="ARP",
                arp_operation=2,
                arp_sender_ip=sender_ip,
                arp_sender_mac=mac,
                arp_target_ip=target_ip,
                arp_target_mac=target_mac,
                src_ip=sender_ip,
                dst_ip=target_ip,
            )
        )
    return records


def unknown_device_traffic(
    src_ip="192.168.1.50",
    dst_ip="192.168.1.1",
    src_port=50000,
    dst_port=22,
    count=5,
    start_time=0.0,
    interval=1.0,
):
    """Traffic from a source that is not in the known-device inventory."""
    return tcp_packets(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        count=count,
        start_time=start_time,
        interval=interval,
    )


def repeated_connections(
    src_ip="10.0.0.1",
    dst_ip="10.0.0.2",
    dst_port=22,
    count=10,
    start_port=40000,
    start_time=0.0,
    interval=0.5,
):
    """Repeated TCP connection attempts to the same destination service.

    Each attempt uses a fresh source port, like a real client reconnecting.
    """
    records = []
    for index in range(count):
        records.append(
            PacketRecord(
                timestamp=start_time + index * interval,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=start_port + index,
                dst_port=dst_port,
                protocol="TCP",
            )
        )
    return records


def _records(count, start_time, interval, **fields):
    return [
        PacketRecord(timestamp=start_time + index * interval, **fields)
        for index in range(count)
    ]
