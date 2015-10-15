#!/usr/local/bin/python
#
# Search the logs in ElasticSearch for 404's on the assumption that those IPs
# are maliciously scanning us. Add them to a list in redis to be blocked by
# block-404.py running on our firewalls.
#
# Tracy Reed
#

# Max number of 404s to allow. More than this and we block them.
MAX404  = 20
# How many minutes into the past to search for 404s
MINUTES = 5

import os
import redis
import socket
import logging
import logging.handlers
import smtplib
import subprocess
from pyes import *
from email.mime.text import MIMEText

# Setup logging to local syslog
log       = logging.getLogger('find-404')
handler   = logging.handlers.SysLogHandler(address = '/dev/log')
formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
log.setLevel(logging.DEBUG)
log.addHandler(handler)
handler.setFormatter(formatter)

def blockips(totals):
    # Find excessive 404's and block them
    for ip in totals:
        log.info('Blocking: %s' % ip)
        if totals[ip] > MAX404:
            # Send IP to firewalls via redis
            r = redis.StrictRedis(host='10.0.2.104', port=6379, db=0)
            r.hset('block404ip', ip, 1)
            # Let someone know about it
            sendmail(ip)
    
def resolveip(ip):
    # Resolve the IP so we have a hostname and possibly general location
    try:
        hostname = socket.gethostbyaddr(ip)[0]
    except socket.herror:
        hostname = "Unknown host"
    return(hostname)

def whois(ip):
    # Do a whois lookup for a little extra intel
    p = subprocess.Popen(['/usr/bin/whois', ip], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = p.communicate()[0]
    return(result)

def sendmail(ip):
    # Set up the email
    blockhost      = resolveip(ip)
    msg            = MIMEText(whois(ip))
    hostname       = os.uname()[1]
    msg['Subject'] = '404 blocked %s[%s]' % (ip, blockhost)
    msg['From']    = "@".join(["block404",hostname])
    msg['To']      = "user@domain.com"
    s              = smtplib.SMTP('localhost')
    # Send it
    s.sendmail(msg['From'], msg['To'], msg.as_string())
    s.quit()

def queryes():
    # Connect to local elasticsearch
    conn = ES('127.0.0.1:9200')
    # Construct our query
    # We want 404 response codes
    q1 = TermQuery("response","404")
    # From 5 minutes ago until now
    q2 = RangeQuery(qrange=ESRange('@timestamp',from_value='now-%dm' % MINUTES,to_value='now'))
    # Except requests for favicon.ico which usually does not exist
    q3 = MatchQuery("request","/favicon.ico")
    q4 = MatchQuery("request","/apple-touch-icon.png")
    q5 = MatchQuery("request","/apple-touch-icon-precomposed.png")
    q  = BoolQuery(must=[q1, q2], must_not=[q3, q4, q5])
    # Execute it
    results = conn.search(query = q)
    return(results)

def count404s(results):
    # Iterate over resulting events totalling up 404's per IP
    counter   = {}
    for r in results:
        total = counter.get(r['clientip'], 0)
        total += 1
        counter[r['clientip']] = total
    return(counter)

def main():
    results   = queryes()
    totals    = count404s(results)
    blockips(totals)

if __name__ == "__main__":
    main()
