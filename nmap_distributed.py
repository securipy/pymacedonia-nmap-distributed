#!/usr/bin/env python
# -*- encoding: utf-8 -*-

""" Nmap Distributed """

import json
import nmap

from .macedonia import MacedoniaPlugin

__author__			= "GoldraK"
__credits__			= "GoldraK"
__version__			= "0.1"
__maintainer__		= "GoldraK"
__email__			= "goldrak@gmail.com"
__status__			= "Development"


class NmapDistributed(MacedoniaPlugin):

	def __init__(self):
		self.detail = {
			'name': "nmap",
			'description': "NMAP Distributed",
			'version': "0.1",
			'log': True,
			'verbose': True,

			'config': {
				'header': "app-granada",
				'domain': "http://api.granada.com",
				'public_key': "1584344601587bdb9a4db022.75409245",
				'private_key': "1331909997587bdb9a4db479.67780769",
			},

			'arguments': [
				{
					'argument': '--verbose'
					'action': 'store_true',
					'help': 'Set verbose level',
				},{
					'argument': '--log'
					'action': 'store_true',
					'help': 'Set log level',
				},
			]
		}

		super().__init__(self.detail['name'], self.detail['description'], self.detail['version'], self.detail['config']['public_key'], self.detail['config']['priv_key'], self.detail['log'], self.detail['verbose'], self.detail['arguments'])

		self.nm = nmap.PortScanner()


	def NmapDistributed(self):
		args = self.__handleArguments()
		token = self.token
		headers = {self.detail['config']['header']:token}

		r = requests.get(self.domain+'/device/nmap/distributed',headers=headers)
		if r.status_code == 200:
			data = json.loads(r.text)
			if(data['response'] == True):
				if not data['result']:
					if self.log:
						self.__writeLog("Not devices to scan")
				else:
					for toscan in data['result']:
						self.__scanDevice(toscan['ip_domain'],toscan['id'])
			else:
				self.__writeLog(data['message'])
		else:
			self.__writeLog(r.text)


	def __scanDevice(self,ip,id_scan):
		msg = "Start scan device: "+ip
		self.__writeLogConsole(msg)
		try:
			self.nm.scan(hosts=ip,arguments="-sV -sC")
		except Exception as e:
			raise e
			self.__writeLog(e)
		for host in self.nm.all_hosts():
		    for proto in nm[host].all_protocols():
		        lport = nm[host][proto].keys()
		        lport = sorted(lport)
		        for port in lport:
		        	r = requests.post(self.domain+'device/nmap/port', data = {'id_scan':id_scan,'port':port,'protocol':nm[host][proto],'state':nm[host][proto][port]['state'],'service':nm[host][proto][port]['product'],'version':nm[host][proto][port]['version'],'banner':nm[host][proto][port]['extrainfo']},headers=headers)
		        	if r.status_code != 200:
	   					data = json.loads(r.text)
	   					if(data['response'] == False):
	   						self.__writeLog(data['message'])


if __name__ == "__main__":
	p = NmapDistributed()
	p.NmapDistributed()
