##!/usr/bin/python
#
# This script monitors configurations of remote machines and updates them
#
import os, hashlib, time, subprocess, thread, datetime, shutil, sys, socket, ssl
from SocketServer import TCPServer, ThreadingMixIn, BaseRequestHandler
from core import *

# check our config directory.
if not os.path.isdir("/var/artillery/client_configs/"):
    os.makedirs("/var/artillery/client_configs/")

# generate ssl certificates if they don't exist
if not os.path.isfile("/var/artillery/pki/server.crt"):
    if not os.path.isdir("/var/artillery/pki/"):
        os.makedirs("/var/artillery/pki/")
    os.system("cd /var/artillery/pki; "
              "openssl req -new -newkey rsa:2048 -days 1200 -nodes -x509 "
              " -keyout server.key -out server.crt -subj \"/\"")

class ClientConfigSocketListener(TCPServer):
    def get_request(self):
            sock, addr = self.socket.accept()
            tlssock = ssl.wrap_socket(sock,
                                      server_side=True,
                                      certfile="/var/artillery/pki/server.crt",
                                      keyfile="/var/artillery/pki/server.key")
            return tlssock, addr

    def handle(self):
        pass

class ClientConfigSocketHandler(BaseRequestHandler):
    def setup(self):
        # get secret from client. Verify
        clientSecret = self.request.recv(1024).rstrip()
        serverSecret = read_config('CONFIG_REMOTE_SECRET')
        if (clientSecret == serverSecret):
            # hopefully this is legit...
            self.request.sendall("OK")
            # get configuration information from client
            configinfo = self.request.recv(1024)
            splitconfig = split_config_info(configinfo)
            configname = splitconfig[0][splitconfig[0].rfind("/")+1:]
            status = chk_configs(splitconfig)
            self.request.sendall(str(status))
            if (status == -1):
                # no copy of config or out of date. Retrieve it
                get_config(self.request, splitconfig[0])
                cleanse_config(splitconfig[0])
                put_config(self.request, splitconfig[0])
                write_log("[*] %s: Artillery Config Manager: %s updated on server" % (grab_time(),configname))
            elif (status == 0):
                # client config out of date
                cleanse_config(splitconfig[0])
                put_config(self.request, splitconfig[0])
                write_log("[*] %s: Artillery Config Manager: %s updated on client" % (grab_time(),configname))
            elif (status == 1):
                # all is well. files are up to date
                write_log("[*] %s: Artillery Config Manager: %s up to date" % (grab_time(),configname))
        self.request.close()

# helper function to get <machinename>:<confighash>:<timestamp>
def split_config_info(clientinfo):
    lconfig = clientinfo.rstrip().split(":")
    lconfig[0] = "/var/artillery/client_configs/" + lconfig[0]
    return lconfig

# analyze hash against server copy of config
def chk_configs(clientinfo):
    configfile = clientinfo[0]
    confighash = clientinfo[1]
    if os.path.isfile(configfile):
        if confighash == hashlib.md5(open(configfile, "r").read()).hexdigest():
            # hashes match, do nothing
            return 1
        else:
            if float(clientinfo[2]) > os.path.getmtime(configfile):
                # client is newer, get that, cleanse return to client
                return -1
            else:
                # server is newer, cleanse and send
                return 0
    # we don't have a server copy. Get one.
    return -1

# this function sets client fields equal to flagged items
def cleanse_config(src):
    # get list of disabled fields
    blocked = read_config("CONFIG_SERVER_DISABLED_ITEMS")
    spblocked= blocked.strip().replace('"', '').replace(' ', '').split(',')
    # only adjust the file if there are disabled items
    if len(spblocked) > 0:
        client_config = open(src, "r")
        strOut = ""
        for line in client_config:
            # ignore comments
            if not line.startswith('#'):
                field = line.strip().split("=")[0]
                if field in blocked:
                    # this field is locked/blocked by master
                    line = field + "=" + read_config(field) + "\n"
            # add line to output string. Modify if necessary
            strOut += line
        client_config.close()
        # reopen config for writing
        client_write = open(src, "w")
        client_write.write(strOut)
        client_write.close()

# retireve remote config
def get_config(connection, dest):
    # get expected size from client
    totsize = int(connection.recv(1024))
    # get known hash from client
    knownhash = connection.recv(1024)
    # get config from client
    fout = open(dest + ".tmp", "w")
    cursize = 0
    tmp = ""
    # alert that we're ready to recv the file
    connection.sendall("letsgobro")
    while cursize < totsize:
        tmp = connection.recv(1024)
        fout.write(tmp)
        cursize = fout.tell()
    fout.close()
    # compare files, discard if hashes don't match
    if knownhash == hashlib.md5(open(dest + ".tmp", "r").read()).hexdigest():
        shutil.move(dest + ".tmp", dest)
    else:
        #os.remove(dest + ".tmp")
        write_log("[!] %s: Artillery Config Manager: ERROR - Invalid config received, discarding" % (grab_time()))

# send config to client
def put_config(connection, conffile):
    # read config file to be sent
    cfin = open(conffile, "r")
    # send size of file
    connection.sendall(str(os.path.getsize(conffile)))
    # send hash of file
    connection.sendall(hashlib.md5(cfin.read()).hexdigest())
    # rewind file
    cfin.seek(0)
    # wait for client ready
    connection.recv(1024)
    # send file
    connection.sendall(cfin.read())
    cfin.close()

# setup thread safe socket server

if is_config_enabled("CONFIG_SERVER"):
    try:
        port = int(read_config("CONFIG_REMOTE_PORT"))
        interface = read_config("BIND_INTERFACE")
        if interface == "":
            server = ClientConfigSocketListener(('0.0.0.0', port), ClientConfigSocketHandler)
        else:
            server = ClientConfigSocketListener(('%s' % interface, port), ClientConfigSocketHandler)
        server.serve_forever()
    except Exception,e:
        write_log("[*] %s: Artillery Config Manager: Unable to start server. Exception: %s" (grab_time(), str(e)))
