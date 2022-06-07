from src import net
from src import arp_spoof
from src import dns_spoof as dns

if __name__ == '__main__':
    net.test()
    input("Press [enter] to start DNS spoofing")
    dns_spoofing = dns.DNSSpoofing(interface="enp0s3", domain_names=["tue.nl"], victims=[], redirect_ip="")
    dns_spoofing.start()
    input("Press [enter] to stop DNS spoofing")
    dns_spoofing.stop()
