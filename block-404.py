#!/usr/local/bin/python
#
# Query redis for list of IPs to blocked which have too many 404's per
# find-404.py run on logstash/ElasticSeach server and block them with
# Shorewall.
#
# Tracy Reed
#

import sys
import redis
import subprocess

redishost=<REDIS_IP_HERE>

# Check if shorewall is running, redirect stdout to avoid noise
result = subprocess.call(["/sbin/shorewall", "status"], stdout=subprocess.PIPE)
if result == 3:
    sys.exit()

ips = []
r   = redis.StrictRedis(host=redishost, port=6379, db=0)
ips = r.hgetall('block404ip')

for ip in ips:
    subprocess.call(["/sbin/shorewall", "drop", ip], stdout=subprocess.PIPE)
