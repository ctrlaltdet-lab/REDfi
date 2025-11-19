import subprocess
import threading
import time
from scapy.all import *

def channel_hopper(interface, stop_event):
    """
    Hops between Wi-Fi channels to find networks.
    """
    channels = [1, 6, 11, 36, 40, 44, 48, 149, 153, 157, 161]
    while not stop_event.is_set():
        for channel in channels:
            if stop_event.is_set():
                break
            try:
                subprocess.run(['iwconfig', interface, 'channel', str(channel)], check=True, capture_output=True, text=True)
                time.sleep(0.5)
            except subprocess.CalledProcessError:
                time.sleep(0.1)

def scan_networks(interface):
    """
    Scans for wireless networks on a given monitor interface.
    """
    networks = []

    def packet_handler(packet):
        if packet.haslayer(Dot11Beacon):
            bssid = packet[Dot11].addr2
            try:
                ssid = packet[Dot11Elt].info.decode()
                if not ssid or '\x00' in ssid:
                    ssid = "<hidden>"
            except UnicodeDecodeError:
                ssid = "<hidden>"
            
            stats = packet[Dot11Beacon].network_stats()
            channel = stats.get("channel")
            
            if bssid not in [net["bssid"] for net in networks]:
                print(f"Found: {ssid} ({bssid}) on channel {channel}")
                networks.append({"ssid": ssid, "bssid": bssid, "channel": channel})

    print(f"[*] Scanning on {interface} with channel hopping for 20 seconds...")

    stop_hopping = threading.Event()
    hopper = threading.Thread(target=channel_hopper, args=(interface, stop_hopping))
    hopper.daemon = True
    hopper.start()

    try:
        sniff(iface=interface, prn=packet_handler, timeout=20)
    except Exception as e:
        print(f"[!] An error occurred during sniffing: {e}")
    finally:
        stop_hopping.set()
        hopper.join()
        print("\n[*] Scan complete.")

    return networks
