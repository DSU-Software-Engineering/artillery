#!/usr/bin/python
# 
# This script checks the server for configuation updates
#
import os, hashlib, time, subprocess, thread, datetime, shutil, sys, socket
from core import *

# this function checks in with the server
def checkin():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = (read_config("CONFIG_REMOTE_HOST"), int(read_config("CONFIG_REMOTE_PORT")))
    print "connecting to ", server_address
    sock.connect(server_address)
    # we're connected, send secret hash
    sock.sendall(hashlib.sha512(read_config("CONFIG_REMOTE_SECRET")).hexdigest())
    # if the socket is still open & we receive OK, continue
    response = sock.recv(4096)
    if (str(response) == "OK"):
        # send our name and hash
        derpstr = socket.gethostname()
        hf = open("/var/artillery/config", "r")
        derpstr += ":" + hashlib.sha512(hf.read()).hexdigest()
        derpstr += ":" + str(os.path.getmtime("/var/artillery/config"))
        print derpstr
        sock.sendall(derpstr)
        # response indicates status on server
        response = sock.recv(4096)
        # -1 means we need to send our stuff to server
        if (response == "-1"):
            print "send new to server"
            sendconfig(sock)
            recvconfig(sock)
        elif (response == "0"):
            print "Local out of date, recv new"
            recvconfig(sock)
        elif (response == "1"):
            print "All is good, later bro!"
        else:
            print "Something wrong..."
    sock.close()

def sendconfig(sock):
    client_file = open("/var/artillery/config", "r")
    sock.sendall(str(os.path.getsize("/var/artillery/config")))
    sock.sendall(client_file.read())
    client_file.close()

def recvconfig(sock):
    recvstr = ""
    totsize = int(sock.recv(4096))
    cursize = 0
    knownhash = sock.recv(4096)
    tmpfile = open("/var/artillery/config.tmp", "w")
    while cursize < totsize:
        tmp = sock.recv(4096)
        tmpfile.write(tmp)
        cursize = tmpfile.tell()
        print "Recv:", cursize, "of", totsize
    tmpfile.close()
    tmpfile = open("/var/artillery/config.tmp", "r")
    tmphash = hashlib.sha512(tmpfile.read()).hexdigest()
    print "tmp:", tmphash, "known:", knownhash
    if (knownhash == tmphash):
        shutil.move("/var/artillery/config.tmp", "/var/artillery/config")
    else:
        print "ERROR: hashes do not match..."
    

checkin()
