#!/usr/bin/python
# This script will hold the functions that will emulate ftp
#
import thread
import socket
import sys
import re
import subprocess
import time
import SocketServer
import os
import random
import datetime
import asynchat
from src.core import *

# This list hold all of the ports emulated by this script
P_LIST = [21]

# Checks to see if protocol is emulated
def protocol_check(port):
	if port in P_LIST:
	    return True

# This would be used if more protocols are adding to this script
def protocol_handler(self):
	port = self.server.server_address[1]
	if port == 21:
		ftp_emulate(self)

# Logging function that calls Dave's logging function
def log(self, rdata):
	try:
		honeypot_ban = is_config_enabled("HONEYPOT_BAN")
		now = str(datetime.datetime.today())
		port = self.server.server_address[1]
		ip = self.client_address[0]
		subject = "%s [!] Artillery has detected an attempt to access protocol on port %s from IP address %s || Attempted command: %s" % (now, port, ip, ' '.join(rdata))
		alert = ""
		if honeypot_ban:
			alert = "%s [!] Artillery has detected command from the IP Address: %s on honeypot restricted port: %s || Attempted command: %s" % (now, ip, port, ' '.join(rdata))
		else:
			alert = "%s [!] Artillery has detected an attack from IP address: %s for a connection on a honeypot port: %s" % (now, ip, port)
		warn_the_good_guys(subject, alert)
	except Exception as E:
		print E

def do_abor(self, rdata):
	self.request.sendall("226 Closing Data Session\n426 Connection Closed\r\n")
	UserCommand = "QUIT"
	log(self, rdata)

def do_cwd(self, rdata):
    print ("200 directory changed to %s" %Param)
    log(self, rdata)

def do_dele(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_get(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_help(self, rdata):
	log(self, rdata)

def do_lcd(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_list(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_lpwd(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_mdtm(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_mkd(self, rdata):
	self.request.sendall("257 ""%s"" directory created" % rdata[1])
	log(self, rdata)

def do_nlst(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_noop(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_pass(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_pasv(self, rdata):
	self.request.sendall("500 Permission denied\r\n")
	log(self, rdata)

def do_port(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_progress(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_put(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_pwd(self, rdata):
	self.request.sendall("257 \"/ftp/guest\" is the current working directory.\r\n")
	log(self, rdata)

def do_quit(self, rdata):
	self.request.close()
	#   if honeypot_ban:
		# ban(self.client_address[0])
	log(self, rdata)

def do_rename(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_retr(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_rmd(self, rdata):
	self.request.sendall("500 Permission denied\r\n")
	print ("227 Entering Passive Mode")
	log(self, rdata)
    
def do_rnfr(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_rnto(self, rdata):
	self.request.sendall("502 Command not implemented\r\n")
	log(self, rdata)
    
def do_site(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_size(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_stor(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_type(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_user(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_version(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_verbose(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_shellcommand(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)
    
def do_escapeshell(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_unrecognized(self, rdata):
    self.request.sendall("502 Command not implemented\r\n")
    log(self, rdata)

def do_syst(self, rdata):
	self.request.sendall("215 UNIX Type: L8\r\n")
	log(self, rdata)

def catch_all(self, rdata):
	self.request.sendall("500 Invalid Command\r\n")
	log(self, rdata)

def do_feat(self, rdata):
	self.request.sendall("211 FEAT\r\n")
	log(self, rdata)

respond = {'?' : do_help,  ###
           'ABOR' : do_abor,
           'BYE' : do_quit,
           'CD' : do_cwd,
           'CWD' : do_cwd,  # CD and CWD
           'DELE' : do_dele,
           'EXIT' : do_quit,  ###
           'GET' : do_get,
           'HELP' : do_help,
           'LCD' : do_lcd,
           'LIST' : do_list,
           'LPWD' : do_lpwd,
           'LS' : do_list,   ###
           'MDTM' : do_mdtm,
           'MKD' : do_mkd,
           'MKDIR' : do_mkd, ###
           'NLST' : do_nlst,
           'NOOP' : do_noop,
           'PASS' : do_pass,
           'PASV' : do_pasv,
           'PORT' : do_port,
           'PROGRESS' : do_progress,
           'PUT' : do_put,
           'PWD' : do_pwd,
           'QUIT' : do_quit,
           'RENAME' : do_rename,
           'RETR' : do_retr,
           'RM' : do_dele, ###
           'RMD' : do_rmd,
           'RMDIR' : do_rmd, ###
           'RNFR' : do_rnfr,
           'RNTO' : do_rnto,
           'SITE' : do_site,
           'SIZE' : do_size,
           'STOR' : do_stor,
           'TYPE' : do_type,
           'USER' : do_user,
           'VERSION' : do_version,
           'VERBOSE' : do_verbose,
           '!COMMAND' : do_shellcommand,
           '!' : do_escapeshell,
           'SYST' : do_syst,
           'FEAT' : do_feat
    }

def ftp_emulate(self):
	try:
		self.request.sendall("220 The date and time is " + datetime.datetime.now().strftime('%a %B %d %H:%M %Y ') + "\r\n")
		rdata = self.request.recv(1024)
		if rdata.lower().strip() == "user anonymous":
			self.request.sendall(
			    "331 Guest login ok, send your email address as password.\r\n")
			try:
			    rdata = self.request.recv(1024)
			    if '@' in rdata.lower():
					self.request.sendall("230 Anonymous access granted, some restrictions apply.\r\n")
					while True:
						rdata = ""
						rdata = self.request.recv(1024)
						rdata = rdata.split(' ')
						print '"' + rdata[0].strip(' \r\n ').upper() + '"'
						try:
							respond[rdata[0].strip(' \r\n ').upper()](self, rdata)
						except:
							catch_all(self)
			except:
				pass
		else:
			self.request.send("something failed - " + rdata.lower().strip() + "\r\n")
	    	self.request.close()
	except Exception, e:
	    print "[!] Error detected. Printing: " + str(e)

	    pass

	# if honeypot_ban:
	# 	ban(self.client_address[0])