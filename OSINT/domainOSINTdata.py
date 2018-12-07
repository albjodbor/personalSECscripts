#General imports
import argparse
import configparser
import sys
import colorama
from colorama import Fore, Back, Style

#Specific libraries imports
import dns.resolver
import dns.exception as DNSexception
import pythonwhois

#Tool imports
import domainOSINTfunctions

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
	creationDate = None
	updateDate = None
	expirationDate = None

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
	def addDNS(self, domainObj):
		self.DNSservers.append(domainObj)

	def printBeautiful(self):
		#Print domain whois info
		print ("-->Creation: " + Fore.BLUE + str(self.creationDate[0]) + Style.RESET_ALL)
		print ("-->Update: " + Fore.BLUE + str(self.updateDate[0]) + Style.RESET_ALL)
		print ("-->Expiration: " + Fore.BLUE + str(self.expirationDate[0]) + Style.RESET_ALL)
		#Print IPv4 List
		for ipv4addess in self.IPv4List:
			print ("--> IPV4: "+ Fore.BLUE + ipv4addess.ip + Style.RESET_ALL)
			if ipv4addess.country is not None:
				print ("----> Country: " + Fore.MAGENTA + ipv4addess.country + Style.RESET_ALL)
			else:
				print ("----> Country: " + Fore.RED + "None" + Style.RESET_ALL)
		#Print IPv6 List
		for ipv6addess in self.IPv6List:
			print ("--> IPV6: "+ Fore.BLUE + ipv6addess.ip + Style.RESET_ALL)
			if ipv6addess.country is not None:
				print ("----> Country: " + Fore.MAGENTA + ipv6addess.country + Style.RESET_ALL)
			else:
				print ("----> Country: " + Fore.RED + "None" + Style.RESET_ALL)
		#Nameservers
		for nameserver in self.DNSservers:
			print ("--> Nameserver: "+ Fore.BLUE + nameserver.name + Style.RESET_ALL)
			if nameserver.ipv4 != "":
				print ("----> IPv4: "+ Fore.CYAN + nameserver.ipv4 + Style.RESET_ALL)
			if nameserver.ipv6 != "":
				print ("----> IPv6: "+ Fore.CYAN + nameserver.ipv6 + Style.RESET_ALL)

#Store a domain element and its related information
class domainElement:
	ipv4 = None
	ipv6 = None
	name = ""
	transfer = False
	country = None
	def __init__(self,domain,ipv4, ipv6):
		self.name = domain
		self.ipv4 = ipv4
		self.ipv6 = ipv6

	def addIPv4 (self, ipv4):
		self.ipv4.append(ipv4)

	def simplePrint(self):
		print (self.domain + " " + self.ipv4 + " " + self.ipv6 + " ")

#Class to store a single ip/name address and its metadata
class IPaddress:
	ip =""
	name=""
	country = None
	def __init__(self,ip, name):
		self.ip=ip
		self.name =name
	