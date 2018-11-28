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

#Description and arguments
parser = argparse.ArgumentParser(
	description="Domain analysis tool for a rapid incident response",
	epilog="Author: Alberto Jodar"
	)
parser.add_argument("domain", help="domain name to investigate")
argumentos = parser.parse_args()

#Start
print ("\nInitiating analysis for domain=[ "
 + Fore.RED + argumentos.domain + Style.RESET_ALL+ 
 " ]...")

#Configure google domain server
print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.RED + "8.8.8.8" + Style.RESET_ALL + " nameserver")
print (Fore.BLUE + "+ " + Style.RESET_ALL + "Using "+ 
	Fore.RED + "8.8.4.4" + Style.RESET_ALL + " nameserver")

resolver = dns.resolver.Resolver(configure=False)
resolver.nameservers = ['8.8.8.8','8.8.4.4']


#Simple query
#To-Do capture (timeout, NXDOMAIN, NoAnswer, NoNameservers)

#Check IPv4
answers = dns.resolver.query(argumentos.domain, 'A')
for rdata in answers:
	print (Fore.BLUE + "--> " + Style.RESET_ALL + "Ipv4 address: " + Fore.RED + str(rdata) + Style.RESET_ALL)
#Check IPv6
answers = dns.resolver.query(argumentos.domain, 'AAAA')
for rdata in answers:
	print (Fore.BLUE + "--> " + Style.RESET_ALL + "Ipv6 address: " + Fore.RED + str(rdata) + Style.RESET_ALL)
