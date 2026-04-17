"""
Live packet capture and PCAP file reader using Scapy.

Provides:
  - capture_live(interface, packet_queue, stop_event): async live TCP sniffer
  - read_pcap(filepath, packet_queue):                 async PCAP file reader
"""

import asyncio

from scapy.all import TCP, rdpcap, sniff


def _packet_to_dict(pkt) -> dict | None:
    """Convert a Scapy TCP packet to a dict.  Returns None for non-TCP."""
    if not pkt.haslayer(TCP):
        return None

    ip = pkt.payload if pkt.haslayer("IP") else None
    tcp = pkt[TCP]

    return {
        "timestamp": float(pkt.time),
        "src_ip":    ip.src if ip else "0.0.0.0",
        "dst_ip":    ip.dst if ip else "0.0.0.0",
        "src_port":  int(tcp.sport),
        "dst_port":  int(tcp.dport),
        "protocol":  "TCP",
        "size":      int(len(pkt)),
        "flags":     str(tcp.flags),
        "window_size": int(tcp.window),
        "seq":       int(tcp.seq),
        "ack":       int(tcp.ack),
        "tcp_layer": "Transport",          # OSI layer for TCP
    }


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------
async def capture_live(interface: str, packet_queue: asyncio.Queue, stop_event: asyncio.Event):
    """
    Start an AsyncSniffer on *interface*, filtering TCP only.
    Each packet is converted to a dict and pushed to *packet_queue*.
    Stops when *stop_event* is set.
    """
    loop = asyncio.get_running_loop()

    def _on_packet(pkt):
        d = _packet_to_dict(pkt)
        if d is not None:
            loop.call_soon_threadsafe(packet_queue.put_nowait, d)

    sniffer = sniff(
        iface=interface,
        filter="tcp",
        prn=_on_packet,
        store=False,
        stop_filter=lambda _: stop_event.is_set(),
        async_sniffer=True,
    )

    await sniffer  # type: ignore[misc]
    # Signal completion
    await packet_queue.put(None)


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------
async def read_pcap(filepath: str, packet_queue: asyncio.Queue):
    """
    Read a PCAP file and push TCP packet dicts to *packet_queue*.
    Pushes a None sentinel when done.
    """
    packets = rdpcap(filepath)
    for pkt in packets:
        d = _packet_to_dict(pkt)
        if d is not None:
            await packet_queue.put(d)
    # Sentinel – tells consumer we're done
    await packet_queue.put(None)
