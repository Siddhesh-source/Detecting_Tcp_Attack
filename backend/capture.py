"""
Live packet capture and PCAP file reader using Scapy.

Provides:
  - capture_live(interface, packet_queue, stop_event): async live multi-protocol sniffer
  - read_pcap(filepath, packet_queue):                 async PCAP file reader
"""

import asyncio
import sys
import platform

from protocol_handlers import packet_to_dict
from scapy.all import rdpcap, sniff


# ---------------------------------------------------------------------------
# Live capture
# ---------------------------------------------------------------------------
async def capture_live(interface: str, packet_queue: asyncio.Queue, stop_event: asyncio.Event):
    """
    Start an AsyncSniffer on *interface*, capturing TCP/UDP/ICMP/DNS.
    Falls back to Windows raw socket if Npcap unavailable.
    """
    print(f"[Capture] Starting live capture on interface: {interface}", file=sys.stderr)
    
    # Check if on Windows and try raw socket fallback
    if platform.system() == "Windows":
        try:
            # Try Scapy first
            from scapy.arch.windows import get_windows_if_list
            print(f"[Capture] Attempting Scapy capture", file=sys.stderr)
        except:
            print(f"[Capture] Scapy unavailable, trying Windows raw socket fallback", file=sys.stderr)
            try:
                from capture_windows import capture_live_windows
                await capture_live_windows(packet_queue, stop_event)
                return
            except Exception as e:
                print(f"[Capture] Windows fallback failed: {e}", file=sys.stderr)
                print(f"[Capture] Install Npcap from https://npcap.com/", file=sys.stderr)
                await packet_queue.put(None)
                return
    
    loop = asyncio.get_running_loop()
    packet_count = 0

    def _on_packet(pkt):
        nonlocal packet_count
        d = packet_to_dict(pkt)
        if d is not None:
            packet_count += 1
            if packet_count % 10 == 0:
                print(f"[Capture] Captured {packet_count} packets", file=sys.stderr)
            loop.call_soon_threadsafe(packet_queue.put_nowait, d)

    try:
        print(f"[Capture] Initializing sniffer with filter: tcp or udp or icmp", file=sys.stderr)
        
        def packet_handler(pkt):
            nonlocal packet_count
            d = packet_to_dict(pkt)
            if d is not None:
                packet_count += 1
                if packet_count % 10 == 0:
                    print(f"[Capture] Captured {packet_count} packets", file=sys.stderr)
                loop.call_soon_threadsafe(packet_queue.put_nowait, d)
        
        # Run sniffer in thread to avoid blocking
        def run_sniffer():
            sniff(
                iface=interface,
                filter="tcp or udp or icmp",
                prn=packet_handler,
                store=False,
                stop_filter=lambda _: stop_event.is_set(),
            )
        
        import threading
        sniffer_thread = threading.Thread(target=run_sniffer, daemon=True)
        sniffer_thread.start()
        
        print(f"[Capture] Sniffer started in background thread", file=sys.stderr)
        
        # Wait for stop event
        while not stop_event.is_set():
            await asyncio.sleep(1)
        
        print(f"[Capture] Stop requested, waiting for sniffer to finish", file=sys.stderr)
        sniffer_thread.join(timeout=5)
        print(f"[Capture] Sniffer stopped. Total packets captured: {packet_count}", file=sys.stderr)
    except Exception as e:
        print(f"[Capture] ERROR: {e}", file=sys.stderr)
        print(f"[Capture] On Windows, install Npcap: https://npcap.com/", file=sys.stderr)
        raise
    finally:
        await packet_queue.put(None)
        print(f"[Capture] Cleanup complete", file=sys.stderr)


# ---------------------------------------------------------------------------
# PCAP reader
# ---------------------------------------------------------------------------
async def read_pcap(filepath: str, packet_queue: asyncio.Queue):
    """
    Read a PCAP file and push TCP/UDP/ICMP/DNS packet dicts to *packet_queue*.
    Pushes a None sentinel when done.
    """
    print(f"[PCAP] Reading file: {filepath}", file=sys.stderr)
    try:
        packets = rdpcap(filepath)
        print(f"[PCAP] Loaded {len(packets)} packets from file", file=sys.stderr)
        
        processed = 0
        for pkt in packets:
            d = packet_to_dict(pkt)
            if d is not None:
                await packet_queue.put(d)
                processed += 1
        
        print(f"[PCAP] Processed {processed} valid packets", file=sys.stderr)
    except Exception as e:
        print(f"[PCAP] ERROR: {e}", file=sys.stderr)
        raise
    finally:
        await packet_queue.put(None)
        print(f"[PCAP] Processing complete", file=sys.stderr)
