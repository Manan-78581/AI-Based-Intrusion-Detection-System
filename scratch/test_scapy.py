
from scapy.all import Ether, ARP, srp
import sys

def test_scan(subnet):
    print(f"Scanning {subnet}...")
    pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
    ans, unans = srp(pkt, timeout=3, verbose=True)
    print(f"Answered: {len(ans)}")
    for sent, recv in ans:
        print(f"Found: {recv.psrc} - {recv.hwsrc}")

if __name__ == "__main__":
    subnet = "172.20.36.0/22"
    if len(sys.argv) > 1:
        subnet = sys.argv[1]
    test_scan(subnet)
