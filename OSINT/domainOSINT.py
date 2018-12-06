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
import configparser
import sys
import colorama
from colorama import Fore, Back, Style

#Specific libraries imports
import dns.resolver
import dns.exception as DNSexception
import dns.zone
import dns.query

#Tool imports
import domainOSINTfunctions
import domainOSINTdata

#Error strings
errorString = ["Timeout!!", "No answer!!", "No exits!!"]

#Description and arguments
parser = argparse.ArgumentParser(
	description="Domain analysis tool for a rapid incident response",
	epilog="Author: Alberto Jodar"
	)
parser.add_argument("domain", help="domain name to investigate")
argumentos = parser.parse_args()

#Configuration parser
config = configparser.ConfigParser()
config.read("domainOSINT.conf")

#Header
print("+------------------------------------------+")
print("|   Domain OSINT investigation tool        |")
print("|                 Author: Alberto Jodar    |")
print("+------------------------------------------+")

#Create object for store results
DomainOSINTObj = domainOSINTdata.DomainOSINT(argumentos.domain)

resolver = dns.resolver.Resolver(configure=False)

#Obtain information from whois
domainOSINTfunctions.domainWHOIS(argumentos.domain, DomainOSINTObj)

#Use specific dns plus static dns list
nameserverList=[]
for (key,nameserver) in config.items("NAMESERVERS"):
	nameserverList.append(nameserver)
	print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.BLUE + nameserver + Style.RESET_ALL + " nameserver")
for nameserverObj in DomainOSINTObj.DNSservers:
	nameserverList.append(nameserverObj.ipv4)
	print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.BLUE + nameserverObj.ipv4 + Style.RESET_ALL + " nameserver")
resolver.nameservers = nameserverList

#Start
print ("Initiating analysis for domain=[ "
 + Fore.BLUE + argumentos.domain + Style.RESET_ALL+ 
 " ]...")

#Check IPv4
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'A'):
	if entry not in errorString:
		address4object = domainOSINTdata.IPaddress(str(entry), argumentos.domain)
		DomainOSINTObj.addIPv4(address4object)
#Check IPv6
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'AAAA'):
	if entry not in errorString:
		address6object = domainOSINTdata.IPaddress(str(entry), argumentos.domain)
		DomainOSINTObj.addIPv6(address6object)
#Check Canonical name
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'CNAME'):
	DomainOSINTObj.addCanonical(str(entry))

DomainOSINTObj.printBeautiful()

#Trying DNS zone transfer
#Except: dns.zone.NoSOA
#Except: dns.zone.NoNS 
for dns_server in DomainOSINTObj.DNSservers:
	print ("Trying DNS transfer for: " + dns_server.ipv4)
	try:
		result_zone = dns.zone.from_xfr(dns.query.xfr(dns_server.ipv4, argumentos.domain))
		print (result_zone)
	except:
		print (Fore.RED + "Not possible!!" + Style.RESET_ALL)
	











