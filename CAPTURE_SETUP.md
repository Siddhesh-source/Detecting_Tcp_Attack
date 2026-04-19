# TCP Covert Channel Detector - Capture Setup

## Problem: Capture not working even with Npcap installed

### Solution:

**1. Run backend as Administrator:**
```bash
# Right-click Command Prompt → "Run as administrator"
cd D:\CN\tcp-covert-channel-detector\backend
python -m uvicorn main:app --host 0.0.0.0 --port 8000
```

**2. Get available interfaces:**
```bash
curl http://localhost:8000/capture/interfaces
```

**3. Use the correct interface name from the list above when starting capture**

### Why Admin is Required:
- Windows requires administrator privileges for raw packet capture
- Npcap driver needs elevated permissions to access network interfaces
- Without admin, capture will fail silently or throw permission errors

### Alternative: Use PCAP file upload instead of live capture
- No admin required
- Upload .pcap files via the UI
- Backend will process them normally
