#!/usr/bin/python3
# -*- coding: utf-8 -*-

# CheckDNS - Simple DNS SOA serial comparison script, checkdns.py
#
# Copyright (C) 2022 Matthew Beeching
#
# This file is part of RelayBot.
#
# RelayBot is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# RelayBot is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with RelayBot.  If not, see <http://www.gnu.org/licenses/>.

import xml.etree.ElementTree as ET
import dns.resolver
import logging, logging.handlers
import argparse, os, sys, time, uuid

# Setup Logging:
class UTCFormatter(logging.Formatter):
    converter = time.gmtime

log = logging.getLogger("checkdns")
log.setLevel(logging.WARNING)
defloghandler = logging.StreamHandler(sys.stdout)
deflogformatter = UTCFormatter('[%(asctime)s] [%(name)s/%(levelname)s] %(message)s', '%Y-%m-%d %H:%M:%S')
defloghandler.setFormatter(deflogformatter)
log.addHandler(defloghandler)

servers = {}
comparisons = []
domains = []

errorres = False

def getconfpath(file=None):
	if file is None:
		file = 'checkdns.xml'

	if os.path.isfile(file):
		return file

	cdir = os.getcwd()
	pdir = os.path.dirname(os.path.realpath(__file__))

	cfile = os.path.join(cdir, file)
	if os.path.isfile(cfile):
		return cfile

	cfile = os.path.join(pdir, file)
	if os.path.isfile(cfile):
		return cfile

	return None

def loadconfig(configfile='checkdns.xml'):
	global servers, comparisons, domains

	try:
		xml = ET.parse(configfile)
	except Exception as e:
		log.error('Error parsing config file: ' + str(e))
		sys.exit(1)

	if xml.getroot().tag != 'checkdns':
		return

	nsuuid = uuid.UUID('7d4c259e-0ece-5ab5-8c6c-bc536b3eb87e')

	for node in xml.findall('./servers/server'):
		name = str(uuid.uuid5(nsuuid, node.text))
		if 'name' in node.attrib:
			name = node.attrib['name']
		srv = dns.resolver.Resolver()
		srv.nameservers = [node.text]
		servers[name] = {'r': srv, 'i': node.text}

	for node in xml.findall('./comparisons/compare'):
		if not 'server1' in node.attrib:
			continue
		if not 'server2' in node.attrib:
			continue
		if not node.attrib['server1'] in servers:
			continue
		if node.attrib['server2'] != '*':
			if not node.attrib['server2'] in servers:
				continue

		s2 = None
		if node.attrib['server2'] != '*':
			s2 = node.attrib['server2']

		comparisons.append([node.attrib['server1'], s2])

	for node in xml.findall('./domains/domain'):
		dom = node.text
		if dom[-1] != '.':
			dom = dom + '.'
		domains.append(dom)

def checkdomain(domain):
	global servers, comparisons
	global errorres

	results = {}

	for srv in servers:
		try:
			log.info('Retrieving SOA record for %s from server %s', domain, srv)
			res = servers[srv]['r'].resolve(domain, 'SOA')
			results[srv] = res.rrset[0].to_text()
		except Exception as e:
			log.warning('Unable to get SOA record for %s from %s: %s', domain, srv, str(e))
			errorres = True
			results[srv] = None

	for cmp in comparisons:
		if cmp[1] is None:
			for srv in servers:
				if srv == cmp[0]:
					continue
				if not srv in results:
					continue
				if results[srv] is None:
					continue
				log.info('Comparing SOA record for %s returned by %s against SOA record for %s returned by %s', domain, cmp[0], domain, srv)
				log.debug('SOA from %s: %s', cmp[0], results[cmp[0]])
				log.debug('SOA from %s: %s', srv, results[srv])
				if results[cmp[0]] != results[srv]:
					log.warning('SOA record for %s returned by %s does not match SOA record returned by %s', domain, srv, cmp[0])
					log.warning('SOA from %s: %s', cmp[0], results[cmp[0]])
					log.warning('SOA from %s: %s', srv, results[srv])
					errorres = True
		else:
			log.info('Comparing SOA record for %s returned by %s against SOA record for %s returned by %s', domain, cmp[0], domain, cmp[1])
			log.debug('SOA from %s: %s', cmp[0], results[cmp[0]])
			log.debug('SOA from %s: %s', cmp[1], results[cmp[1]])
			if results[cmp[0]] != results[cmp[1]]:
				log.warning('SOA record for %s returned by %s does not match SOA record returned by %s', domain, cmp[1], cmp[0])
				log.warning('SOA from %s: %s', cmp[0], results[cmp[0]])
				log.warning('SOA from %s: %s', cmp[1], results[cmp[1]])
				errorres = True

def main():
	ap = argparse.ArgumentParser(description='Simple DNS SOA serial check script', add_help=False)
	ap.add_argument('-h', '-?', '--help', help='Show this help message and exit', action='help')
	ap.add_argument('-c', '--config', help='Specify the path to a config file', action='store', default='checkdns.xml', dest='config')
	ap.add_argument('-d', '--debug', help='Enable debug mode', action='store_true', dest='debug')
	ap.add_argument('-v', '--verbose', help='Enable verbose logging', action='store_true', dest='verbose')
	args = ap.parse_args()

	if args.verbose:
		log.setLevel(logging.INFO)
	elif args.debug:
		log.setLevel(logging.DEBUG)
	cfile = getconfpath(args.config)

	log.debug('specified config file: %s', args.config)
	log.debug('config file: %s', cfile)
	log.debug('log level: %s', str(log.getEffectiveLevel()))

	if cfile is None:
		log.error('Cannot find config file')
		sys.exit(1)

	loadconfig(cfile)

	for dom in domains:
		checkdomain(dom)

	if errorres:
		log.setLevel(logging.INFO)
		log.info('Servers:')

		for srv in servers:
			log.info(srv + ': ' + servers[srv]['i'])

if __name__ == "__main__":
	main()
