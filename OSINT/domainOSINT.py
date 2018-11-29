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

#Error strings
errorString = ["Timeout!!", "No answer!!", "No exits!!"]

#Class for store information about domain
class DomainOSINT:
	#Lists of singleDomains
	IPv4List = []
	IPv6List = []
	canonicalName = []
	Mailservers = []
	DNSservers = []

	def __init__(self,domain):
		self.domain = domain

	def addIPv4 (self, ipv4):
		self.IPv4List.append(ipv4)
	def addIPv6 (self, ipv6):
		self.IPv6List.append(ipv6)
	def addCanonical (self, canonical):
		self.canonicalName.append(canonical)
	def addMail(self, domainObj):
		self.Mailservers.append(domainObj)

	def printBeautiful(self):
		#Header message
		print ("Stored data for domain: " + 
			Fore.CYAN + self.domain + Style.RESET_ALL)

		#Print IPv4 List
		print (Fore.BLUE + "--> " + Style.RESET_ALL + "IPv4: ")
		for address in self.IPv4List:
			if str(address) in errorString:
				print (Fore.BLUE + "----> " + 
					Fore.RED + str(address) + 
					Style.RESET_ALL)
			else:
				print (Fore.BLUE + "----> " + 
					Fore.CYAN + str(address) + 
					Style.RESET_ALL)
		#Print IPv6 List
		print (Fore.BLUE + "--> " + Style.RESET_ALL + "IPv6: ")
		for address in self.IPv6List:
			if str(address) in errorString:
				print (Fore.BLUE + "----> " + 
					Fore.RED + str(address) + 
					Style.RESET_ALL)
			else:
				print (Fore.BLUE + "----> " + 
					Fore.CYAN + str(address) + 
					Style.RESET_ALL)		
		#Print Canonical names List
		print (Fore.BLUE + "--> " + Style.RESET_ALL + "Canonical names: ")
		for name in self.canonicalName:
			if str(name) in errorString:
				print (Fore.BLUE + "----> " + 
					Fore.RED + str(name) + 
					Style.RESET_ALL)
			else:
				print (Fore.BLUE + "----> " + 
					Fore.CYAN + str(name) + 
					Style.RESET_ALL)
		#Print Mail servers list
		print (Fore.BLUE + "--> " + Style.RESET_ALL + "Mail servers: ")
		for mailServer in self.Mailservers:
			if mailServer.domain in errorString:
				print (Fore.BLUE + "----> " + 
					Fore.RED + mailServer.domain + 
					Style.RESET_ALL)
			else:
				print (Fore.BLUE + "----> " + 
					Fore.CYAN + mailServer.domain + 
					Style.RESET_ALL)
				#Print its IPv4 and IPv6
				print (Fore.BLUE + "------> " + 
					Fore.CYAN + mailServer.ipv4 + 
					Style.RESET_ALL)
				print (Fore.BLUE + "------> " + 
					Fore.CYAN + mailServer.ipv6 + 
					Style.RESET_ALL)


#Store a simple domain/ip pair
class singleDomain:
	ipv4 = ""
	ipv6 = ""
	domain = ""
	def __init__(self,domain,ipv4, ipv6):
		self.domain = domain
		self.ipv4 = ipv4
		self.ipv6 = ipv6

	def simplePrint(self):
		print (self.domain + " " + self.ipv4 + " " + self.ipv6 + " ")
		
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

def mailQuery(domain, domainObject):
	try:
		answer = dns.resolver.query(domain, "MX")
		for entry in answer:
			mailIPv4 = singleQuery (str(entry[0], "A"))
			mailIPv6 = singleQuery (str(entry[0], "AAAA"))
			domainObj = singleDomain(str(entry[0], mailIPv4, mailIPv6))
			domainObject.addMail(domainObj)
	except dns.resolver.Timeout:
		domainObj = singleDomain("Timeout!!","","")
		domainObject.addMail(domainObj)
	except dns.resolver.NoAnswer:
		domainObj = singleDomain("No answer!!","","")
		domainObject.addMail(domainObj)
	except dns.resolver.NXDOMAIN:
		domainObj = singleDomain("No exits!!","","")
		domainObject.addMail(domainObj)

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
#Check Canonical name
for entry in singleQuery(argumentos.domain, 'CNAME'):
	DomainOSINTObj.addCanonical(str(entry))

#Check MAIL
mailQuery (argumentos.domain, DomainOSINTObj)

#TODO: Check DNS server --> NS


DomainOSINTObj.printBeautiful()



