#!/usr/bin/env python

# Copyright (c) 2016 Thomas Nicholson <tnnich@googlemail.com>
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
# 1. Redistributions of source code must retain the above copyright
#    notice, this list of conditions and the following disclaimer.
# 2. Redistributions in binary form must reproduce the above copyright
#    notice, this list of conditions and the following disclaimer in the
#    documentation and/or other materials provided with the distribution.
# 3. The names of the author(s) may not be used to endorse or promote
#    products derived from this software without specific prior written
#    permission.
#
# THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
# OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
# AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
# OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
# OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
# SUCH DAMAGE.

from honssh.config import Config
from honssh.utils import validation
from honssh import log

import datetime
import time
from time import gmtime, strftime, localtime
import os
import re
import MySQLdb
import ConfigParser
import geoip2.database
import collections
import json
from pyes import *


class Plugin(object):
    def __init__(self):
        self.cfg = Config.getInstance()
        self.server = None
	host=self.cfg.get(['output-elasticsearch', 'host']),
        port=self.cfg.get(['output-elasticsearch', 'port']),
        user=self.cfg.get(['output-elasticsearch', 'username']),
        passwd=self.cfg.get(['output-elasticsearch', 'password']),
	tup1={'username':user,'password':passwd}
	es = ES(server=host[0]+":"+port[0], basic_auth=tup1)
	try:
		es.indices.create_index("attacks")
	except:
		print "already there"
	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'username': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'password': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'entered_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     }
	}
	es.indices.put_mapping("ssh_auth_details", {'properties':mapping}, ["attacks"])

	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'country': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'location': {
		 'store': 'yes',
		 'type': 'geo_point',
	     },
	     'attack_start_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     },
	     'attack_end_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     }
	}
	es.indices.put_mapping("ssh_connections", {'properties':mapping}, ["attacks"])
	
	mapping = {
	     'ip': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'country': {
		 'store': 'yes',
		 'type': 'keyword',
	     },
	     'location': {
		 'store': 'yes',
		 'type': 'geo_point',
	     },
	     'attack_time': {
		 'store': 'yes',
		 'type': 'date',
		 'format' : 'dd MMM yyyy HH:mm:ss'
	     },
	     'protocol': {
		 'store': 'yes',
		 'type': 'keyword',
	     }
	}
	es.indices.put_mapping("connections", {'properties':mapping}, ["attacks"])

    def connect_esserver(self):
        host=self.cfg.get(['output-elasticsearch', 'host']),
        port=self.cfg.get(['output-elasticsearch', 'port']),
        user=self.cfg.get(['output-elasticsearch', 'username']),
        passwd=self.cfg.get(['output-elasticsearch', 'password']),
	tup1={'username':user,'password':passwd}
	print host
	print port
	es = ES(server=host[0]+":"+port[0], basic_auth=tup1)
	return es

    def start_server(self):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', 'START SERVER')

    def set_server(self, server):
        self.server = server
	

    def connection_made(self, sensor):
	session = sensor['session']
	country=""
	city=""
	location=""
	starting_time=datetime.datetime.strptime(session['start_time'],'%Y%m%d_%H%M%S_%f').strftime('%d %b %Y %H:%M:%S')
	reader = geoip2.database.Reader("/home/kp/proxies/GeoLite2-City.mmdb")
	try:
		rez = reader.city(session['peer_ip'])

		country=rez.country.name
		city=rez.city.name
		location=str(rez.location.latitude)+","+str(rez.location.longitude)
	except:
			print "not found"
	auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = session['peer_ip']
	auth_dict1['country'] = country
	auth_dict1['city'] = city
	auth_dict1['location'] = location
	auth_dict1['attack_time'] = starting_time
	auth_dict1['protocol'] = "ssh"
	auth_json = json.dumps(auth_dict1)
	es=self.connect_esserver()
	es.index(auth_json, 'attacks', 'connections')
        
    def connection_lost(self, sensor):
        session = sensor['session']
	country=""
	city=""
	location=""
	starting_time=datetime.datetime.strptime(session['start_time'],'%Y%m%d_%H%M%S_%f').strftime('%d %b %Y %H:%M:%S')
	ending_time=datetime.datetime.strptime(session['end_time'],'%Y%m%d_%H%M%S_%f').strftime('%d %b %Y %H:%M:%S')
	reader = geoip2.database.Reader("/home/kp/proxies/GeoLite2-City.mmdb")
	try:
		rez = reader.city(session['peer_ip'])

		country=rez.country.name
		city=rez.city.name
		location=str(rez.location.latitude)+","+str(rez.location.longitude)
	except:
			print "not found"
	auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = session['peer_ip']
	auth_dict1['country'] = country
	auth_dict1['city'] = city
	auth_dict1['location'] = location
	auth_dict1['attack_start_time'] = starting_time
	auth_dict1['attack_end_time'] = ending_time
	auth_json = json.dumps(auth_dict1)
	es=self.connect_esserver()
	es.index(auth_json, 'attacks', 'ssh_connections')

    def set_client(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def login_successful(self, sensor):
	session = sensor['session']
	auths = sensor['session']['auth']
        auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = session['peer_ip']
	auth_dict1['username'] = auths['username']
	auth_dict1['password'] = auths['password']
	auth_dict1['entered_time'] = datetime.datetime.strptime(auths['date_time'],'%Y%m%d_%H%M%S_%f').strftime('%d %b %Y %H:%M:%S')
	auth_json = json.dumps(auth_dict1)
	print auth_json
	es=self.connect_esserver()
	es.index(auth_json, 'attacks', 'ssh_auth_details')


    def login_failed(self, sensor):
	session = sensor['session']
	auths = sensor['session']['auth']
        auth_dict1 = collections.OrderedDict()
	auth_dict1['ip'] = session['peer_ip']
	auth_dict1['username'] = auths['username']
	auth_dict1['password'] = auths['password']
	auth_dict1['entered_time'] = datetime.datetime.strptime(auths['date_time'],'%Y%m%d_%H%M%S_%f').strftime('%d %b %Y %H:%M:%S')
	auth_json = json.dumps(auth_dict1)
	print auth_json
	es=self.connect_esserver()
	es.index(auth_json, 'attacks', 'ssh_auth_details')

    def channel_opened(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def channel_closed(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def command_entered(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def download_started(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def download_finished(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def packet_logged(self, sensor):
        log.msg(log.PLAIN, '[PLUGIN][EXAMPLE]', sensor)

    def validate_config(self):
        props = [['output-elasticsearch', 'enabled']]
        for prop in props:
            if not self.cfg.check_exist(prop, validation.check_valid_boolean):
                return False
	return True

    
