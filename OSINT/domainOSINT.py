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

#Dictionary to translate queries in human code
DNSqueries = {
	"A":"IPv4", 
	"AAAA":"IPv6", 
	"MX":"Mailservers"
	}

#Format answer of dns queries
def formatAnswer (singleAnswer, queryType):
	try:
		answersResult = Fore.BLUE + "--> " + Style.RESET_ALL + DNSqueries[queryType] + ": " + Fore.BLUE + str(singleAnswer) + Style.RESET_ALL
	except:
		answersResult = ""
	return answersResult

#Perform simple dns queries
def singleQuery(domain, queryType):
	#Lists to store results
	PrintAnswerList = []
	try:
		answers = dns.resolver.query(domain, queryType)
		for rdata in answers:
			PrintAnswerList.append(formatAnswer(rdata, queryType))
	except dns.resolver.Timeout:
		PrintAnswerList.append(Fore.BLUE + "--> " + Style.RESET_ALL + DNSqueries[queryType] + ": " + Fore.RED + "Timeout!!" + Style.RESET_ALL)
	except dns.resolver.NoAnswer:
		PrintAnswerList.append(Fore.BLUE + "--> " + Style.RESET_ALL + DNSqueries[queryType] + ": " + Fore.RED + "No answer!!" + Style.RESET_ALL)
	except dns.resolver.NXDOMAIN:
		PrintAnswerList.append(Fore.BLUE + "--> " + Style.RESET_ALL + DNSqueries[queryType] + ": " + Fore.RED + "No exits!!" + Style.RESET_ALL)

	return PrintAnswerList


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

#Check IPv4
answer = singleQuery(argumentos.domain, 'A')
for entry in answer:
	print (entry)
#Check IPv6
answer = singleQuery(argumentos.domain, 'AAAA')
for entry in answer:
	print (entry)
#Check MAIL
answer = singleQuery(argumentos.domain, 'MX')
for entry in answer:
	print (entry)