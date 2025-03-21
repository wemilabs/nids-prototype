from scapy.all import *
import time

target_ip = "127.0.0.1"
for port in range(1, 15):
    send(IP(dst=target_ip)/TCP(dport=port, flags="S"), verbose=0)
    time.sleep(0.1)  # Small delay to avoid overwhelming
print("Port scan simulation complete.")