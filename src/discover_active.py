"""
Assignment for course 2IC80, Lab on Offensive Computer Security, at TU/e
Created by;
Daan Boelhouwers(1457152), d.boelhouwers@student.tue.nl
Richard Farla(1420380), r.farla@student.tue.nl
Ivar de Win(1406663), i.j.f.d.win@student.tue.nl
"""

from scapy.arch import get_if_addr
from scapy.error import Scapy_Exception
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import sendp


def discover(interface: str):
    try:
        ip = f"{get_if_addr(interface)}/24"
        frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        sendp(frame, iface=interface, verbose=False)
    except OSError:
        print(f"Could not open the adapter for interface {interface}")
    except Scapy_Exception:
        print(f"Could not operate on interface {interface}")
