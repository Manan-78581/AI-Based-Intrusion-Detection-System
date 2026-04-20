
import sys
import os

# Add project root to path
sys.path.append(os.getcwd())

from backend.scanner.arp_scanner import _get_local_subnet

if __name__ == "__main__":
    print(f"Detected: {_get_local_subnet()}")
