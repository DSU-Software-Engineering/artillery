#127.0.0.1 - - [10/Mar/2012:15:35:53 -0500] "GET /sdfsdfds.dsfds HTTP/1.1" 404 501 "-" "Mozilla/5.0 (X11; Linux i686 on x86_64; rv:10.0.2) Gecko/20100101 Firefox/10.0.2"
import re, datetime
from core import *
from time import *
checker = 0

def tail(some_file):
    this_file = open(some_file)
    # Go to the end of the file
    this_file.seek(0,2)

    while True:
        line = this_file.readline()
        if line:
            yield line
        else:
        	sleep(5)
		
def persistant_404(apache_file):
	# create a record of each time a 404 occurred with each IP
	ipList = []
	ip404counter = []
	ipAlertList = []
	now = str(datetime.datetime.today())
	# search for 404's
	for line in apache_file:
		if '404' in line:
			# parse ip from line and record the activity in the parallel arrays
			ipList.append(re.findall( r'[0-9]+(?:\.[0-9]+){3}', s ))
			if ip in ipList:
				index = ipList.index(ip)
				ip404counter[index] = ip404counter[index] + 1
			else:
				ipList.append(ip)
				ip404counter.append(1)
				
	# if the number of times a 404 is initiated by the IP exceeds a number ( 15 ) then record that in a list
	ipAlertList = [j for (i,j) in zip(ipList, ip404counter) if i >= 15]
	
	# ban if over 20 and not on whitelist and let the good guys know
	for ip, count in ipAlertList:
		if count >= 20:
			check_whitelist = is_whitelisted_ip(ip)
			if check_whitelist == 0:
				#ban that ip address************************************---------------------*******************************
				subject = "%s [!] Artillery has BLOCKED the IP Address: %s" % (now, ip)
				ban(ip) #sends ip to ban function for banning
		else:
			subject = "%s [!] Artillery has detected %s 404 errors from the IP Address: %s" % (now, count, ip)
			
		alert = "Artillery has detected a possible attack from IP address: %s after initiating multiple 404 errors." % (ip)
		warn_the_good_guys(subject, alert)

def ban_on_404(apache_file):
	hits = {}
	# prepare to read logs
	logfile = tail(apache_file)
	for line in logfile:
		# if not line:
		# 	# if none is generated, wait awhile, there will be more log entries
		# 	print "waiting...",
		# 	sleep(5)
		# 	continue
		if '404' in line:
			linevars = line.split()
			if linevars[8] == '404':
				ip = linevars[0]
				if not is_whitelisted_ip(ip):
					ts = mktime(datetime.datetime.strptime(linevars[3][1:], '%d/%b/%Y:%H:%M:%S').timetuple())
					if ip in hits:
						notify, stamps = hits[ip]
						stamps.append(ts)
						hits[ip] = (notify,stamps)
					else:
						hits[ip] = (0, [ts])
					print ip, hits[ip] # Debugging only
					
					# remove timestamps not in last 24 hours
					then = time() - 86400
					newlist = []
					notify, stamps = hits[ip]
					for stamp in stamps:
						if stamp > then:
							newlist.append(stamp)

					# log
					now = grab_time()
					subject = "%s [!] Artillery has detetected a 404 from %s. %s in last 24 hours" % (now,ip,len(newlist))
					write_log(subject)

					# ban pending configuration; email if necessary
					if is_config_enabled("NUM_404"):
						if len(newlist) >= int(read_config("NUM_404") and not notify):
							ban(ip)
							warn_the_good_guys(subject,"IP address banned forever based on configuration settings. Login to machine and run remove_ban.py <ip> to remove.")
							notify = 1


# grab the access logs and tail them
access = "/var/log/apache2/access.log"
access_log = tail(access)

if checker >= 100:
	# check persistent 404's from access logs
	persistant_404(access)
	checker = 0
	
checker = checker + 1

# grab the error logs and tail them
errors = "/var/log/apache2/error.log"
error_log = tail(errors)
