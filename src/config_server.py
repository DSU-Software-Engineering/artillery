##!/usr/bin/python
#
# This script monitors configurations of remote machines and updates them
#
import os, hashlib, time, subprocess, thread, datetime, shutil, sys, socket
from core import *

# check our config directory.
if not os.path.isdir("/var/artillery/client_configs/"):
    os.makedirs("/var/artillery/client_configs/")

# function to monitor socket
def serve():
    mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    myaddress = ('localhost', int(read_config('CONFIG_REMOTE_PORT')))
    mysock.bind(myaddress)
    mysock.listen(100)
    while True:
        connection, client_address= mysock.accept()
        print "Connection received from:", client_address
        clienthash = connection.recv(4096).rstrip()
        serverhash = hashlib.sha512(read_config('CONFIG_REMOTE_SECRET')).hexdigest()
        print "SERVER:", serverhash, "CLIENT:", clienthash
        if (clienthash == serverhash):
            # hopefully this is legit...
            connection.sendall("OK")
            configinfo = connection.recv(4096)
            splitconfig = split_config_info(configinfo) 
            status = chk_configs(splitconfig)
            connection.sendall(str(status))
            if (status == -1):
                # receive config file here, cleanse, return
                get_config(connection, splitconfig[0])
                cleanse_config(splitconfig[0])
                put_config(connection, splitconfig[0])
            elif (status == 0):
                # send config file to client here
                cleanse_config(splitconfig[0])
                put_config(connection, splitconfig[0])
        connection.close()

def split_config_info(clientinfo):
    lconfig = clientinfo.rstrip().split(":")
    lconfig[0] = "/var/artillery/client_configs/" + lconfig[0]
    return lconfig

def chk_configs(clientinfo):
    # we'll check for machineinfo in our database here
    configfile = clientinfo[0]
    confighash = clientinfo[1]
    if os.path.isfile(configfile):
        print "Config " + configfile  + " found, checking..."
        if confighash == hashlib.sha512(open(configfile, "r").read()).hexdigest():
            print "Valid hash"
            return 1
        else:
            print "Invalid hash"
            if float(clientinfo[2]) > os.path.getmtime(configfile):
                # client is newer, get that, cleanse return -1
                return -1
            else:
                # server is newer, cleanse and send
                return 0
    return -1

def cleanse_config(src):
    blocked = read_config("CONFIG_SERVER_DISABLED_ITEMS")
    spblocked= blocked.strip().replace('"', '').replace(' ', '').split(',')
    client_config = open(src, "r")
    strOut = ""
    for x in spblocked:
        print x
    for line in client_config:
        if not line.startswith('#'):
            field = line.strip().split("=")[0]
            if field in blocked:
                # this field is locked/blocked by master
                line = field + "=" + read_config(field) + "\n"
        strOut += line
    client_config.close()
    client_write = open(src, "w")
    client_write.write(strOut)
    client_write.close()

def get_config(connection, dest):
    strOut = ""
    cursize = 0
    totsize = int(connection.recv(4096))
    fout = open(dest, "w")
    while cursize < totsize:
        tmp = connection.recv(4096)
        fout.write(tmp)
        cursize = fout.tell()
        print "Recv",cursize,"of",totsize
    fout.close()

def put_config(connection, conffile):
    cfin = open(conffile, "r")
    print "cfin", conffile
    connection.sendall(str(os.path.getsize(conffile)))
    connection.sendall(hashlib.sha512(cfin.read()).hexdigest())
    cfin.seek(0)
    connection.sendall(cfin.read())
    cfin.close()
    
serve()
