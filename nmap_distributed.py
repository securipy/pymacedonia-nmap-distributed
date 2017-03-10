#!/usr/bin/env python3
# -*- encoding: utf-8 -*-

""" Nmap Distributed """

import json
import nmap
import requests

from macedonia import MacedoniaPlugin

__author__          = "GoldraK"
__credits__         = "GoldraK"
__version__         = "0.1"
__maintainer__      = "GoldraK"
__email__           = "goldrak@gmail.com"
__status__          = "Development"


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
                'public_key': "1212740469589f806e2187c5.01211814",
                'private_key': "241732944589f806e218921.91958991",
            },

            'arguments': [
                {
                    'argument': '--verbose',
                    'action': 'store_true',
                    'help': 'Set verbose level',
                },{
                    'argument': '--log',
                    'action': 'store_true',
                    'help': 'Set log level',
                },
            ]
        }

        super().__init__(self.detail['name'], self.detail['description'], self.detail['version'], self.detail['config']['public_key'], self.detail['config']['private_key'], self.detail['log'], self.detail['verbose'], self.detail['arguments'])

        self.nm = nmap.PortScanner()


    def NmapDistributed(self):
      #  args = self.__handleArguments()
    
        headers = {self.detail['config']['header']:self.jwt}

        r = requests.get(self.detail['config']['domain']+'/device/nmap/distributed',headers=headers)
        if r.status_code == 200:
            data = json.loads(r.text)
            if(data['response'] == True):
                if not data['result']:
                    if self.detail['log']:
                        self.writeLogConsole("Not devices to scan",True)
                else:
                    for toscan in data['result']:
                        self.__scanDevice(toscan['ip'],toscan['id'],toscan['id_work'])
            else:
                self.writeLogConsole(data['message'],True)
        else:
            self.writeLogConsole(r.text,True)


    def __scanDevice(self,ip,id_scan,id_work):

        headers = {self.detail['config']['header']:self.jwt}
        
        msg = "Start scan device: "+ip
        self.writeLogConsole(msg)
        try:
            self.nm.scan(hosts=ip,arguments="-sV -sC")
        except Exception as e:
            raise e
            self.writeLog(e)
        for host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                lport = self.nm[host][proto].keys()
                lport = sorted(lport)
                for port in lport:
                    r = requests.post(self.detail['config']['domain']+'/device/nmap/port', data = {'id_scan':id_scan,'id_work':id_work,'port':port,'protocol':self.nm[host][proto],'state':self.nm[host][proto][port]['state'],'service':self.nm[host][proto][port]['product'],'version':self.nm[host][proto][port]['version'],'banner':self.nm[host][proto][port]['extrainfo']},headers=headers)
                    if r.status_code != 200:
                        data = json.loads(r.text)
                        if(data['response'] == False):
                            self.writeLogConsole(data['message'])
                        else:
                            self.writeLogConsole(data['message'],True)
                    else:
                        self.writeLogConsole(r.text,True)


if __name__ == "__main__":
    p = NmapDistributed()
    p.NmapDistributed()
