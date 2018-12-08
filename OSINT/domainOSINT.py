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
import geoip2.database

#Tool imports
import domainOSINTfunctions
import domainOSINTdata

#General values
errorString = ["Timeout!!", "No answer!!", "No exits!!"]




# Description and arguments
#---------------------------------
parser = argparse.ArgumentParser(
	description="Domain analysis tool for a rapid incident response",
	epilog="Author: Alberto Jodar"
	)
#Domain to be investigated
parser.add_argument("domain", help="domain name to investigate")
argumentos = parser.parse_args()


# Configuration file
#---------------------------------
config = configparser.ConfigParser()
config.read("domainOSINT.conf")

# Header
#---------------------------------
print(" ____                        _        ___  ____ ___ _   _ _____  ")
print("|  _ \\  ___  _ __ ___   __ _(_)_ __  / _ \\/ ___|_ _| \\ | |_   _| ")
print("| | | |/ _ \\| '_ ` _ \\ / _` | | '_ \\| | | \\___ \\| ||  \\| | | |   ")
print("| |_| | (_) | | | | | | (_| | | | | | |_| |___) | || |\\  | | |   ")
print("|____/ \\___/|_| |_| |_|\\__,_|_|_| |_|\\___/|____/___|_| \\_| |_|   ")
print("___________________________________________________________________")
print("                 	Author: " + Fore.CYAN + "Alberto Jodar (@albjodbor)" + Style.RESET_ALL)
print("")

# First configuration
#---------------------------------
#Create main object for store results
DomainOSINTObj = domainOSINTdata.DomainOSINT(argumentos.domain)
#Configure dns resolver
resolver = dns.resolver.Resolver(configure=False)
#Read GeoIP database
geoIPdb = geoip2.database.Reader('geoIP.mmdb')

# WHOIS search. Dates and DNS list
#---------------------------------
whoisResult = domainOSINTfunctions.domainWHOIS(argumentos.domain)
if whoisResult is not None:
	#Store reation, update and expiration dates
	DomainOSINTObj.creationDate = whoisResult["creation_date"]
	DomainOSINTObj.updateDate = whoisResult["updated_date"]
	DomainOSINTObj.expirationDate = whoisResult["expiration_date"]
	#Store DNS servers
	for nameserver in whoisResult["nameservers"]:
		#For each dns in the list create domain element
		NSDomainElement = domainOSINTdata.domainElement (nameserver)

		#Peform simple queries for IPv4
		nameserverIPv4 = domainOSINTfunctions.singleQuery(nameserver, 'A')
		for ip4address in nameserverIPv4:
			#For each IP Address if not an error
			if str(ip4address) not in errorString:
				#Create address object
				IpAdress4Object = domainOSINTdata.IPaddress(str(ip4address))
				#Fill with geoIP info
				geoIPresult = geoIPdb.country(str(ip4address))
				IpAdress4Object.country = geoIPresult.country.name
				#Append to DomainElement IPv4 List
				NSDomainElement.AddressIPv4.append(IpAdress4Object)
			else:
				print (Fore.RED + "Error obtaining IPV4 for: " + nameserver + 
					" Error: " + str(ip4address) + Style.RESET_ALL)

		#Peform simple queries for IPv6
		nameserverIPv6 = domainOSINTfunctions.singleQuery(nameserver, 'AAAA')
		for ip6address in nameserverIPv6:
			#For each IP Address if not an error
			if str(ip6address) not in errorString:
				#Create address object
				IpAdress6Object = domainOSINTdata.IPaddress(str(ip6address))
				#Fill with geoIP info
				geoIPresult = geoIPdb.country(str(ip6address))
				IpAdress6Object.country = geoIPresult.country.name
				#Append to DomainElement IPv4 List
				NSDomainElement.AddressIPv6.append(IpAdress6Object)
			else:
				print (Fore.RED + "Error obtaining IPV6 for: " + nameserver + 
					" Error: " + str(ip6address) + Style.RESET_ALL)
else:
	print (Fore.RED + "Error obtaining WHOIS for: " + argumentos.domain + Style.RESET_ALL)


# Add DNS to list
#---------------------------------
nameserverList=[]
for (key,nameserver) in config.items("NAMESERVERS"):
	nameserverList.append(nameserver)
	print ("+ Using "+ Fore.BLUE + nameserver + Style.RESET_ALL + " nameserver")
for nameserverObj in DomainOSINTObj.DNSservers:
	nameserverList.append(nameserverObj.IPAddress)
	print ("+ Using "+ Fore.BLUE + nameserverObj.IPAddress + Style.RESET_ALL + " nameserver")
resolver.nameservers = nameserverList

# DNS queries
#---------------------------------
#Starting message
print ("\nInitiating analysis for domain=[ " + Fore.BLUE + 
	argumentos.domain + Style.RESET_ALL+  " ]...")


#Query for IPv4
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'A'):
	if entry not in errorString:
		#Create address object
		IpAdress4Object = domainOSINTdata.IPaddress(str(entry))
		#Fill with geoIP info
		geoIPresult = geoIPdb.country(str(entry))
		IpAdress4Object.country = geoIPresult.country.name
		#Append to DomainElement IPv4 List
		DomainOSINTObj.IPv4List.append(IpAdress4Object)
	else:
		print (Fore.RED + "Error obtaining IPV4 for: " + argumentos.domain + 
					" Error: " + str(entry) + Style.RESET_ALL)

#Query for IPv6
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'AAAA'):
	if entry not in errorString:
		#Create address object
		IpAdress6Object = domainOSINTdata.IPaddress(str(entry))
		#Fill with geoIP info
		geoIPresult = geoIPdb.country(str(entry))
		IpAdress6Object.country = geoIPresult.country.name
		#Append to DomainElement IPv4 List
		DomainOSINTObj.IPv6List.append(IpAdress4Object)
	else:
		print (Fore.RED + "Error obtaining IPV6 for: " + argumentos.domain + 
					" Error: " + str(entry) + Style.RESET_ALL)

#Check Canonical name
for entry in domainOSINTfunctions.singleQuery(argumentos.domain, 'CNAME'):
	DomainOSINTObj.addCanonical(str(entry))

DomainOSINTObj.printBeautiful()

#Trying DNS zone transfer
for dns_server in DomainOSINTObj.DNSservers:
	print ("--> Trying DNS transfer for: " + Fore.BLUE + dns_server.name + Style.RESET_ALL, end=" --> ")
	try:
		result_zone = dns.zone.from_xfr(dns.query.xfr(dns_server.ipv4, argumentos.domain))
		print (Fore.CYAN + "Possible!!" + Style.RESET_ALL)
		dns_server.PossibleTransfer = True
	except:
		print (Fore.RED + "Not possible!!" + Style.RESET_ALL)
	











