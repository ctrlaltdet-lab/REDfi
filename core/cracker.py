from pyrcrack import aircrack
import os

def crack_password(wordlist):
    """
    Cracks the WPA password using a wordlist if a handshake file exists.
    """
    if not os.path.exists("handshake.pcap"):
        print("[!] Handshake file not found. Skipping cracking process.")
        return

    print("[*] Cracking password with wordlist...")
    try:
        # The class is Aircrack (capital A) inside the aircrack module
        cracker_instance = aircrack.Aircrack(wordlist=wordlist, capfile="handshake.pcap")
        password = cracker_instance.crack()
        if password:
            print(f"[+] SUCCESS! Password found: {password}")
        else:
            print("[-] Password not found in the provided wordlist.")
    except Exception as e:
        print(f"[!] An error occurred during cracking: {e}")
