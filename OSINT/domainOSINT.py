#!/usr/bin/env python

#--------------------------------------------------------------
#	Simple script to perform authomatic analysis over an
#	specific domain name. Main usage for incident response
#
#	usage: python3 domainOSINT.py <domain>
#
#--------------------------------------------------------------

#General imports
import argparse
import sys
import colorama
from colorama import Fore, Back, Style

#Specific libraries imports
import dns.resolver
import dns.exception as DNSexception

#Class for store information about domain
class DomainOSINT:
	#Lists of singleDomains
	IPv4List = []
	IPv6List = []
	Mailservers = []
	DNSservers = []

	def __init__(self,domain):
		self.domain = domain

	def addIPv4 (self, ipv4):
		self.IPv4List.append(ipv4)
	def addIPv6 (self, ipv4):
		self.IPv6List.append(ipv4)

	def printBeautiful(self):
		print ("TODO")

#Store a simple domain/ip pair
class singleDomain:
	ip = ""
	domain = ""
	def __init__(self,domain,ip):
		self.domain = domain
		self.ip = ip
		
#Perform simple dns queries
def singleQuery(domain, queryType):
	try:
		answer = dns.resolver.query(domain, queryType)
	except dns.resolver.Timeout:
		answer= ["Timeout!!"]
	except dns.resolver.NoAnswer:
		answer= ["No answer!!"]
	except dns.resolver.NXDOMAIN:
		answer= ["No exits!!"]
	return answer


#Description and arguments
parser = argparse.ArgumentParser(
	description="Domain analysis tool for a rapid incident response",
	epilog="Author: Alberto Jodar"
	)
parser.add_argument("domain", help="domain name to investigate")
argumentos = parser.parse_args()

#Start
print ("\nInitiating analysis for domain=[ "
 + Fore.BLUE + argumentos.domain + Style.RESET_ALL+ 
 " ]...")

#Configure google domain server
print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.BLUE + "8.8.8.8" + Style.RESET_ALL + " nameserver")
print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.BLUE + "8.8.4.4" + Style.RESET_ALL + " nameserver")

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8','8.8.4.4']

#Create object for store results
DomainOSINTObj = DomainOSINT(argumentos.domain)

#Check IPv4
for entry in singleQuery(argumentos.domain, 'A'):
	DomainOSINTObj.addIPv4(str(entry))
#Check IPv6
for entry in singleQuery(argumentos.domain, 'AAAA'):
	DomainOSINTObj.addIPv6(str(entry))
#Check MAIL --> MX
#TODO
#Check DNS server --> NS
#TODO