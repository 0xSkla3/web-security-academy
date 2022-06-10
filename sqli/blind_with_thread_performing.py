#!/usr/bin/python3

from pwn import *
import requests
import string
import threading
import signal
import time


def sigint_handler(signal, frame):
    print("\n\n[*] Saliendo...\n")
    sys.exit(1)

signal.signal(signal.SIGINT, sigint_handler)

if (len(sys.argv) != 2):
    log.failure("Use: %s <url>" % sys.argv[0])
    sys.exit(1)

url = sys.argv[1]
payload = 
characters = strings.2

def check_lengh_build():
   payload = "' "  


def main():
    p1 = log.progress("Brute force")
    p2 = log.progress("Password")
    p1.status("Initialize")
    time.sleep(2)
    s = requests.Session()
    request_inicial = s.get()
    check_length_payload = check_length_build()
    
if __name__ == "__main__":
    main()
