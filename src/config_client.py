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
    sock.connect(server_address)
    # we're connected, send secret hash
    sock.sendall(hashlib.sha512(read_config("CONFIG_REMOTE_SECRET")).hexdigest())
    # if the socket is still open & we receive OK, continue
    response = sock.recv(1024)
    if (str(response) == "OK"):
        # send our name and hash
        myinfo = socket.gethostname()
        hf = open("/var/artillery/config", "r")
        myinfo += ":" + hashlib.sha512(hf.read()).hexdigest()
        myinfo += ":" + str(os.path.getmtime("/var/artillery/config"))
        sock.sendall(myinfo)
        # response indicates status on server
        response = sock.recv(1024)
        if (response == "-1"):
            # server out of date or the like
            sendconfig(sock)
            recvconfig(sock)
            write_log(timenow() + " Artillery Config Manager: Sent local config to server. Recevied cleansed version")
        elif (response == "0"):
            # client out of date or the like
            recvconfig(sock)
            write_log(timenow() + " Artillery Config Manager: Updated local configuration from server")
        elif (response == "1"):
            # everything is up to date. do nothing
            write_log(timenow() + " Artillery Config Manager: Local configuration is up to date")
        else:
            write_log(timenow() + " Artillery Config Manager: ERROR: Invalid status from server...")
    sock.close()

# return current time
def timenow():
    return str(datetime.datetime.now())

# send config over socket
def sendconfig(sock):
    client_file = open("/var/artillery/config", "r")
    # send expected size
    sock.sendall(str(os.path.getsize("/var/artillery/config")))
    # send hash of file
    sock.sendall(hashlib.sha512(client_file.read()).hexdigest())
    # rewind file
    client_file.seek(0)
    # send file
    sock.sendall(client_file.read())
    sock.sendall("acm-endoffile")
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
    while True:
        tmp = sock.recv(1024)
        tmpfile.write(tmp)
        cursize = tmpfile.tell()
    tmpfile.close()
    # compare hash to received file
    tmpfile = open("/var/artillery/config.tmp", "r")
    tmphash = hashlib.sha512(tmpfile.read()).hexdigest()
    if (knownhash == tmphash):
        shutil.move("/var/artillery/config.tmp", "/var/artillery/config")
    else:
        os.remove("/var/artillery/config.tmp")
        write_log(timenow() + " Artillery Config Manager: invalid hash on received config, discarding config.tmp")

# starts client process
def runClient():
    timeout = read_config("CONFIG_FREQUENCY")
    write_log(timenow() + " Artillery Config Manager: Client process started, checking every " + str(timeout) + " seconds")
    while True:
        thread.start_new_thread(checkin, ())
        time.sleep(int(timeout))

runClient()
