# -------------------------------------------------
#  AI-IDS  -  ARP Network Scanner
#  Scans local subnet every SCAN_INTERVAL seconds.
#  Detects new nodes and updates MongoDB.
# -------------------------------------------------
import asyncio
import socket
from datetime import datetime, timezone

from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp

from database.mongo_client import nodes_col
from backend.state import state

SCAN_INTERVAL = 5         # Reduced for faster detection
ARP_TIMEOUT   = 2         # seconds to wait for ARP replies
SUBNET        = "172.20.32.0/22"   # ← Updated for hostel LAN network


def _get_local_subnet() -> str:
    """Auto-detect subnet from machine IP and subnet mask."""
    try:
        import subprocess
        # Get network interface info
        result = subprocess.run(['ipconfig'], capture_output=True, text=True, shell=True)
        lines = result.stdout.split('\n')
        
        current_ip = None
        current_mask = None
        found_active = False
        
        for i, line in enumerate(lines):
            # Look for adapters with an IPv4 address
            if 'IPv4 Address' in line:
                ip_part = line.split(':')[-1].strip()
                # Skip loopback and VM adapters if possible, or just take the one that has a gateway
                # We'll look ahead or back for "Default Gateway"
                
                # Check if this adapter has a Default Gateway in the next few lines
                has_gateway = False
                for j in range(i, min(i + 10, len(lines))):
                    if 'Default Gateway' in lines[j] and ':' in lines[j]:
                        gateway_val = lines[j].split(':')[-1].strip()
                        if gateway_val:
                            has_gateway = True
                            break
                
                if has_gateway:
                    current_ip = ip_part
                    # Find Subnet Mask for this adapter
                    for j in range(max(0, i-5), min(i + 5, len(lines))):
                        if 'Subnet Mask' in lines[j]:
                            current_mask = lines[j].split(':')[-1].strip()
                            break
                    found_active = True
                    break
        
        if not found_active:
            # Fallback: just take the first 172. or 192. address
            for line in lines:
                if 'IPv4 Address' in line:
                    ip_part = line.split(':')[-1].strip()
                    if ip_part.startswith('172.') or ip_part.startswith('192.'):
                        current_ip = ip_part
                        break
        
        if current_ip and current_mask:
            # Calculate network address
            ip_parts = [int(x) for x in current_ip.split('.')]
            mask_parts = [int(x) for x in current_mask.split('.')]
            
            network_parts = []
            for ip_part, mask_part in zip(ip_parts, mask_parts):
                network_parts.append(ip_part & mask_part)
            
            network = '.'.join(str(x) for x in network_parts)
            
            # Calculate CIDR notation
            cidr = sum(bin(int(x)).count('1') for x in mask_parts)
            
            # Try to set scapy interface
            try:
                from scapy.config import conf
                from scapy.arch.windows import get_windows_if_list
                
                # On Windows, we want the GUID of the adapter
                # We can try to match by IP
                for iface in get_windows_if_list():
                    if 'ips' in iface and current_ip in iface['ips']:
                        # On Windows, scapy wants the name like "Ethernet" or the GUID
                        # Setting conf.iface to the scapy-compatible name
                        # Actually, scapy on windows often uses the 'name' or 'description'
                        pass 
            except:
                pass

            return f"{network}/{cidr}"
            
    except Exception as e:
        print(f"Subnet detection error: {e}")
    
    return SUBNET


def _arp_scan(subnet: str) -> list[dict]:
    """
    Send ARP broadcast to the subnet.
    Returns list of {ip, mac} dicts for responding hosts.
    """
    try:
        from scapy.config import conf
        # On Windows, scapy sometimes picks the wrong interface.
        # We can try to let scapy handle it, but if it fails, we might need to be explicit.
        
        # print(f"[Scanner] Scapy using interface: {conf.iface}")
        pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
        
        # INCREASE TIMEOUT slightly for busy networks
        answered, _ = srp(pkt, timeout=ARP_TIMEOUT, verbose=False)
        
        results = []
        for sent, received in answered:
            results.append({
                "ip":  received.psrc,
                "mac": received.hwsrc.upper(),
            })
        
        if not results:
            print(f"[Scanner] Scan on {subnet} returned 0 results.")
        else:
            print(f"[Scanner] Scan on {subnet} found {len(results)} live nodes.")
            
        return results
    except Exception as e:
        print(f"[Scanner] ARP scan error: {e}")
        import traceback
        traceback.print_exc()
        return []


async def run_scanner(ws_broadcast_fn):
    """
    Continuous ARP scan loop.
    ws_broadcast_fn: coroutine called with a WebSocket event dict
                     whenever a new node is detected.
    """
    subnet = _get_local_subnet()
    print(f"[Scanner] Detected subnet: {subnet}")
    print(f"[Scanner] Starting ARP scan on {subnet} every {SCAN_INTERVAL}s")

    col = nodes_col()

    while True:
        if state.detection_enabled:
            try:
                live_nodes = await asyncio.get_event_loop().run_in_executor(
                    None, _arp_scan, subnet
                )
                
                if live_nodes:
                    print(f"[Scanner] Scan complete: found {len(live_nodes)} nodes")
                else:
                    # Optional: print even if 0 found for debugging
                    # print("[Scanner] Scan complete: no nodes found")
                    pass

                now = datetime.now(timezone.utc).isoformat()

                for node in live_nodes:
                    ip  = node["ip"]
                    mac = node["mac"]

                    existing = await col.find_one({"ip": ip})

                    if existing is None:
                        # -- Brand-new node -------------------------
                        doc = {
                            "ip":         ip,
                            "mac":        mac,
                            "status":     "active",
                            "risk_level": "safe",
                            "first_seen": now,
                            "last_seen":  now,
                        }
                        await col.insert_one(doc)
                        print(f"[Scanner] (NEW) New node: {ip} ({mac})")

                        await ws_broadcast_fn({
                            "event": "new_node",
                            "data": {
                                "ip":         ip,
                                "mac":        mac,
                                "status":     "active",
                                "risk_level": "safe",
                                "timestamp":  now,
                            },
                        })
                    else:
                        # -- Known node - update last_seen & status -
                        await col.update_one(
                            {"ip": ip},
                            {"$set": {"last_seen": now, "status": "active", "mac": mac}},
                        )
            except Exception as e:
                print(f"[Scanner] Error during scan: {e}")
        
        if state.detection_enabled:
            await asyncio.sleep(SCAN_INTERVAL)
        else:
            await asyncio.sleep(1)  # Check status more frequently when disabled
