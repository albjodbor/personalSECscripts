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

#Store a domain element and its related information
class domainElement:
	DomainName = None
	AddressIPv4 = []
	AddressIPv6 = []
	PossibleTransfer = False

	def __init__(self,domain):
		self.DomainName = domain

	def simplePrint(self):
		print (self.domain + " " + self.ipv4 + " " + self.ipv6 + " ")

#Class to store a single ip/name address and its metadata
class IPaddress:
	IPAddress = None
	country = None

	def __init__(self,ip):
		self.IPAddress=ip


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
		#Print Canonical name
		for name in self.canonicalName:
			if name not in errorString:
				print ("-->Canonical name: " + Fore.BLUE + name + Style.RESET_ALL)
			else:
				print ("-->Canonical name: " + Fore.RED + name + Style.RESET_ALL)

		#Print whois date
		print ("-->Creation: " + Fore.BLUE + str(self.creationDate[0]) + Style.RESET_ALL)
		print ("-->Update: " + Fore.BLUE + str(self.updateDate[0]) + Style.RESET_ALL)
		print ("-->Expiration: " + Fore.BLUE + str(self.expirationDate[0]) + Style.RESET_ALL)

		#Print IPv4 List
		for ipv4addess in self.IPv4List:
			print ("--> IPV4: "+ Fore.BLUE + ipv4addess.IPAddress + Style.RESET_ALL)
			if ipv4addess.country is not None:
				print ("----> Country: " + Fore.MAGENTA + ipv4addess.country + Style.RESET_ALL)
			else:
				print ("----> Country: " + Fore.RED + "None" + Style.RESET_ALL)
		#Print IPv6 List
		for ipv6addess in self.IPv6List:
			print ("--> IPV6: "+ Fore.BLUE + ipv6addess.IPAddress + Style.RESET_ALL)
			if ipv6addess.country is not None:
				print ("----> Country: " + Fore.MAGENTA + ipv6addess.country + Style.RESET_ALL)
			else:
				print ("----> Country: " + Fore.RED + "None" + Style.RESET_ALL)
		#Print Nameservers
		for nameserver in self.DNSservers:
			print ("--> Nameserver: "+ Fore.BLUE + nameserver.name + Style.RESET_ALL)
			for address in nameserver.AddressIPv4:
				print ("----> IPv4: "+ Fore.CYAN + address.IPAddress + Style.RESET_ALL)
				if address.country is not None:
					print ("------> Country: " + Fore.MAGENTA + address.country + Style.RESET_ALL)
				else:
					print ("------> Country: " + Fore.RED + "None" + Style.RESET_ALL)
			for address in nameserver.AddressIPv6:
				print ("----> IPv6: "+ Fore.CYAN + address.IPAddress + Style.RESET_ALL)
				if address.country is not None:
					print ("------> Country: " + Fore.MAGENTA + address.country + Style.RESET_ALL)
				else:
					print ("------> Country: " + Fore.RED + "None" + Style.RESET_ALL)
			if nameserver.PossibleTransfer == True:
				print ("----> Possible Zone Transfer: " + Fore.BLUE + "True!!" + tyle.RESET_ALL)
			else:
				print ("----> Possible Zone Transfer: " + Fore.RED + "False!!" + tyle.RESET_ALL)

	