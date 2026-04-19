"""
Windows-compatible capture fallback using socket sniffing.
Works without Npcap/WinPcap by using raw sockets (requires admin).
"""
import asyncio
import socket
import struct
import sys
from typing import Optional


async def capture_live_windows(packet_queue: asyncio.Queue, stop_event: asyncio.Event):
    """
    Windows raw socket capture (requires admin privileges).
    Fallback when Npcap/WinPcap not available.
    """
    print("[Capture] Starting Windows raw socket capture (admin required)", file=sys.stderr)
    
    try:
        # Create raw socket
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((socket.gethostbyname(socket.gethostname()), 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        s.settimeout(1.0)
        
        print("[Capture] Raw socket initialized", file=sys.stderr)
        packet_count = 0
        
        while not stop_event.is_set():
            try:
                data, addr = s.recvfrom(65535)
                packet_count += 1
                
                if packet_count % 10 == 0:
                    print(f"[Capture] Captured {packet_count} packets", file=sys.stderr)
                
                # Parse IP header
                packet_dict = parse_raw_packet(data, addr[0])
                if packet_dict:
                    await packet_queue.put(packet_dict)
                    
            except socket.timeout:
                continue
            except Exception as e:
                print(f"[Capture] Packet processing error: {e}", file=sys.stderr)
                continue
        
        print(f"[Capture] Stopped. Total packets: {packet_count}", file=sys.stderr)
        
    except PermissionError:
        print("[Capture] ERROR: Admin privileges required for raw socket capture", file=sys.stderr)
        raise
    except Exception as e:
        print(f"[Capture] ERROR: {e}", file=sys.stderr)
        raise
    finally:
        try:
            s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            s.close()
        except:
            pass
        await packet_queue.put(None)


def parse_raw_packet(data: bytes, src_ip: str) -> Optional[dict]:
    """Parse raw IP packet to extract basic flow info."""
    try:
        if len(data) < 20:
            return None
        
        # IP header
        ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
        version_ihl = ip_header[0]
        ihl = (version_ihl & 0xF) * 4
        protocol = ip_header[6]
        src = socket.inet_ntoa(ip_header[8])
        dst = socket.inet_ntoa(ip_header[9])
        
        # Only TCP/UDP/ICMP
        if protocol not in [1, 6, 17]:
            return None
        
        packet_dict = {
            "timestamp": asyncio.get_event_loop().time(),
            "src_ip": src,
            "dst_ip": dst,
            "size": len(data),
            "protocol": {1: "ICMP", 6: "TCP", 17: "UDP"}.get(protocol, "UNKNOWN")
        }
        
        # Parse transport layer
        if protocol == 6 and len(data) >= ihl + 20:  # TCP
            tcp_header = struct.unpack('!HHLLBBHHH', data[ihl:ihl+20])
            packet_dict.update({
                "src_port": tcp_header[0],
                "dst_port": tcp_header[1],
                "seq": tcp_header[2],
                "ack": tcp_header[3],
                "flags": tcp_header[5],
                "window_size": tcp_header[6],
            })
        elif protocol == 17 and len(data) >= ihl + 8:  # UDP
            udp_header = struct.unpack('!HHHH', data[ihl:ihl+8])
            packet_dict.update({
                "src_port": udp_header[0],
                "dst_port": udp_header[1],
            })
        elif protocol == 1 and len(data) >= ihl + 8:  # ICMP
            icmp_header = struct.unpack('!BBH', data[ihl:ihl+4])
            packet_dict.update({
                "src_port": 0,
                "dst_port": 0,
                "icmp_type": icmp_header[0],
                "icmp_code": icmp_header[1],
            })
        else:
            packet_dict.update({"src_port": 0, "dst_port": 0})
        
        return packet_dict
        
    except Exception as e:
        return None
