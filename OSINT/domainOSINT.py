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
print ("Initiating analysis for domain=[ " +argumentos.domain+ " ] ...\n")

#Simple query
