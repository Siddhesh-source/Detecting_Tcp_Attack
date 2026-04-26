"""
Live packet capture and PCAP file reader using Scapy.

Provides:
  - capture_live(interface, packet_queue, stop_event): async live multi-protocol sniffer
  - read_pcap(filepath, packet_queue):                 async PCAP file reader
"""

import asyncio
import sys
import platform
import threading

from protocol_handlers import packet_to_dict
from scapy.all import rdpcap, AsyncSniffer


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------
async def capture_live(interface: str, packet_queue: asyncio.Queue, stop_event: asyncio.Event):
    """
    Start an AsyncSniffer on *interface*, capturing TCP/UDP/ICMP/DNS.
    Uses Scapy's AsyncSniffer which runs correctly on Windows with Npcap.
    Logs a heartbeat every 5 seconds showing the running packet count.
    """
    print(f"[Capture] Starting live capture on interface: {interface}", flush=True)
    print(f"[Capture] Platform: {platform.system()} {platform.release()}", flush=True)

    loop = asyncio.get_running_loop()
    packet_count = 0
    sniffer_error: list = []  # mutable container to surface thread errors

    def _on_packet(pkt):
        nonlocal packet_count
        try:
            d = packet_to_dict(pkt)
            if d is not None:
                packet_count += 1
                loop.call_soon_threadsafe(packet_queue.put_nowait, d)
        except Exception as e:
            print(f"[Capture] Packet parse error: {e}", flush=True)

    try:
        print(f"[Capture] Initializing AsyncSniffer — filter: tcp or udp or icmp", flush=True)

        sniffer = AsyncSniffer(
            iface=interface,
            filter="tcp or udp or icmp",
            prn=_on_packet,
            store=False,
        )

        sniffer.start()
        print(f"[Capture] AsyncSniffer started — waiting for packets...", flush=True)

        # Heartbeat loop: log packet count every 5 seconds
        heartbeat_interval = 5
        elapsed = 0
        while not stop_event.is_set():
            await asyncio.sleep(1)
            elapsed += 1
            if elapsed % heartbeat_interval == 0:
                print(
                    f"[Capture] Heartbeat — {packet_count} packets captured so far "
                    f"(elapsed {elapsed}s, interface={interface})",
                    flush=True,
                )

        print(f"[Capture] Stop requested — stopping AsyncSniffer...", flush=True)
        sniffer.stop()
        print(f"[Capture] AsyncSniffer stopped. Total packets captured: {packet_count}", flush=True)

    except Exception as e:
        print(f"[Capture] ERROR starting AsyncSniffer: {type(e).__name__}: {e}", flush=True)
        print(f"[Capture] Ensure Npcap is installed (https://npcap.com/) and you are running as Administrator.", flush=True)
        raise
    finally:
        await packet_queue.put(None)
        print(f"[Capture] Cleanup complete.", flush=True)


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------
async def read_pcap(filepath: str, packet_queue: asyncio.Queue):
    """
    Read a PCAP file and push TCP/UDP/ICMP/DNS packet dicts to *packet_queue*.
    Pushes a None sentinel when done.
    """
    print(f"[PCAP] Reading file: {filepath}", flush=True)
    try:
        packets = rdpcap(filepath)
        print(f"[PCAP] Loaded {len(packets)} packets from file", flush=True)

        processed = 0
        for pkt in packets:
            d = packet_to_dict(pkt)
            if d is not None:
                await packet_queue.put(d)
                processed += 1

        print(f"[PCAP] Processed {processed} valid packets", flush=True)
    except Exception as e:
        print(f"[PCAP] ERROR: {e}", flush=True)
        raise
    finally:
        await packet_queue.put(None)
        print(f"[PCAP] Processing complete", flush=True)
