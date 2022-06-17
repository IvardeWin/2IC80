from scapy.arch import get_if_addr
from scapy.error import Scapy_Exception
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp


def discover(interface: str):
    try:
        ip = f"{get_if_addr(interface)}/24"
        frame = ARP(pdst=ip) / Ether(dst="ff:ff:ff:ff:ff:ff")
        frame.show()
        sendp(frame, iface=interface, timeout=2, verbose=False)
    except OSError:
        print(f"Could not open the adapter for interface {interface}")
    except Scapy_Exception:
        print(f"Could not operate on interface {interface}")
