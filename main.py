from src import net
from src import dns_spoof as dns

if __name__ == '__main__':
    net.test()
    input("Press [enter] to start DNS spoofing")
    dns_spoofing = dns.DNSSpoofing(interface=[], domain_names=[], victims=[], redirect_ip="")
    dns_spoofing.start()
    input("Press [enter] to stop DNS spoofing")
    dns_spoofing.stop()
