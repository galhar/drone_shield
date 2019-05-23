# Writer: Gal Harari
# Date: 22/05/2019$
from get_control import Controller

if __name__=="__main__":
    controller = Controller()

    controller.handler_ip = '192.168.10.2'
    controller.drone_ip = '192.168.10.1'
    controller.drone_mac = '60:60:1f:c4:3d:ba'
    controller.handler_mac = 'ec:d0:9f:fd:1b:25'

    adir_ip = '192.168.43.148'
    adir_mac = '00:f4:8d:cc:9d:8d'
    phones_ip = '192.168.43.1'
    phones_mac = 'f0:e4:3e:79:36:18'


    controller.drone_ip = adir_ip
    controller.drone_mac = adir_mac
    controller.handler_mac=phones_mac
    controller.handler_ip=phones_ip


    # controller._get_macs()
    controller._spoof()

