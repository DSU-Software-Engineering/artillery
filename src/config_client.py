#!/usr/bin/python
#
# This script checks the server for configuation updates
#
import os, hashlib, time, subprocess, thread, datetime, shutil, sys, socket, ssl
from core import *

# this function checks in with the server
def checkin():
    rawsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (read_config("CONFIG_REMOTE_HOST"), int(read_config("CONFIG_REMOTE_PORT")))
    sock = ssl.wrap_socket(rawsock)
    sock.connect(server_address)

    if verifyThumbprint(sock) == False:
        sock.close()
        return

    # we're connected, send secret
    sock.sendall(read_config("CONFIG_REMOTE_SECRET"))
    # if the socket is still open & we receive OK, continue
    response = sock.recv(1024)
    if (str(response) == "OK"):
        # send our name and hash
        myinfo = socket.gethostname()
        hf = open("/var/artillery/config", "r")
        myinfo += ":" + hashlib.md5(hf.read()).hexdigest()
        myinfo += ":" + str(os.path.getmtime("/var/artillery/config"))
        sock.sendall(myinfo)
        # response indicates status on server
        response = sock.recv(1024)
        if (response == "-1"):
            # server out of date or the like
            sendconfig(sock)
            recvconfig(sock)
            write_log("[*] %s: Artillery Config Manager: Sent local config to server. Recevied cleansed version" % (grab_time()))
        elif (response == "0"):
            # client out of date or the like
            recvconfig(sock)
            write_log("[*] %s: Artillery Config Manager: Updated local configuration from server" % (grab_time()))
        elif (response == "1"):
            # everything is up to date. do nothing
            write_log("[*] %s: Artillery Config Manager: Local configuration is up to date" % (grab_time()))
        else:
            write_log("[!] %s: Artillery Config Manager: Invalid status from server..." % (grab_time()))
    sock.close()

# send config over socket
def sendconfig(sock):
    client_file = open("/var/artillery/config", "r")
    # send expected size
    sock.sendall(str(os.path.getsize("/var/artillery/config")))
    # send hash of file
    sock.sendall(hashlib.md5(client_file.read()).hexdigest())
    # rewind file
    client_file.seek(0)
    # wait for server ready...
    sock.recv(1024)
    # send file
    sock.sendall(client_file.read())
    client_file.close()

# receive config
def recvconfig(sock):
    # get expected size
    totsize = int(sock.recv(1024))
    cursize = 0
    # get expected hash
    knownhash = sock.recv(1024)
    # get and store file
    tmpfile = open("/var/artillery/config.tmp", "w")
    # alert server ready
    sock.sendall("come at me bro")
    tmp = ""
    while cursize < totsize:
        tmp = sock.recv(1024)
        tmpfile.write(tmp)
        cursize = tmpfile.tell()
    tmpfile.close()
    # compare hash to received file
    tmpfile = open("/var/artillery/config.tmp", "r")
    tmphash = hashlib.md5(tmpfile.read()).hexdigest()
    if (knownhash == tmphash):
        shutil.move("/var/artillery/config.tmp", "/var/artillery/config")
    else:
        os.remove("/var/artillery/config.tmp")
        write_log("[!] %s: Artillery Config Manager: invalid hash on received config, discarding config.tmp" % (grab_time()))

def verifyThumbprint(socket):
    rawThumbprint = hashlib.sha1(socket.getpeercert(True)).hexdigest()
    thumbprint = ':'.join(rawThumbprint[i:i+2] for i in range (0, len(rawThumbprint), 2)).upper()

    if (os.path.isfile("/var/artillery/configServerThumbprint")):
        knownThumbprint = open("/var/artillery/configServerThumbprint", 'r').read()
        if (knownThumbprint == thumbprint):
            return True
        else:
            write_log("[!] %s: Artillery Config Manager: invalid server thumbprint %s" % (grab_time(), thumbprint))
            return False
    else:
        open("/var/artillery/configServerThumbprint", "w").write(thumbprint)
        return True

# starts client process
def runClient():
    timeout = read_config("CONFIG_FREQUENCY")
    write_log("[*] %s: Artillery Config Manager: Client process started, checking every x %s seconds" % (grab_time(), str(timeout)))
    while True:
        thread.start_new_thread(checkin, ())
        time.sleep(int(timeout))

thread.start_new_thread(runClient,())
