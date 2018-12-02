#General imports
import argparse
import configparser
import sys
import colorama
from colorama import Fore, Back, Style

#Specific libraries imports
import dns.resolver
import dns.exception as DNSexception

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
		#Print IPv4 List
		for ipv4addess in self.IPv4List:
			print ("--> IPV4: "+ ipv4addess.ip)
		#Print IPv6 List
		for ipv6addess in self.IPv6List:
			print ("--> IPV6: "+ ipv6addess.ip)

#Store a simple domain/ip pair
class domainElement:
	ipv4 = []
	ipv6 = []
	name = ""
	def __init__(self,domain,ipv4, ipv6):
		self.name = domain
		self.ipv4 = ipv4
		self.ipv6 = ipv6

	def __init__(self,domain):
		self.name = domain

	def addIPv4 (self, ipv4):
		self.ipv4.append(ipv4)

	def simplePrint(self):
		print (self.domain + " " + self.ipv4 + " " + self.ipv6 + " ")

#Ipv4 adress class
class IPv4address:
	ip =""
	def __init__(self,ipv4):
		self.ip=ipv4


#Ipv6 adress class
class IPv6address:
	ip =""
	def __init__(self,ipv6):
		self.ip=ipv6

	