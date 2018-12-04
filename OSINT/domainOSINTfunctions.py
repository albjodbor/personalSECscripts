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
import domainOSINTdata

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

def elementQuery(domain, query):
	returnedElement = domainOSINTdata.domainElement(domain)

	try:
		answer = dns.resolver.query(domain, query)
	except (dns.resolver.Timeout, 
		dns.resolver.NoAnswer, 
		dns.resolver.NXDOMAIN):
		print("No answer for query type: " + query + " for domain: " + domain )
		return 0
	
	for entry in answer:
		#Obtain lis of IPv4 of this element
		try:
			listIPv4 = singleQuery (str(entry[0]), "A")
			for ipv4 in listIPv4:
				addressIPv4Obj = domainOSINTdata.IPv4address(str(ipv4))
				returnedElement.addIPv4(addressIPv4Obj)
		except (dns.resolver.Timeout, 
		dns.resolver.NoAnswer, 
		dns.resolver.NXDOMAIN):
			print("No answer for query type: A for domain: " + str(entry) )

		#Obtain lis of IPv6 of this element
		try:	
			listIPv6 = singleQuery (str(entry[0]), "AAAA")
			for ipv6 in listIPv6:
				addressIPv6Obj = domainOSINTdata.IPv6address(str(ipv6))
				returnedElement.addIPv6(addressIPv6Obj)
		except (dns.resolver.Timeout, 
		dns.resolver.NoAnswer, 
		dns.resolver.NXDOMAIN):
			print("No answer for query type: AAAA for domain: " + str(entry) )
	
	return returnedElement

#Perform a whois search of a domain and store relevant data
def domainWHOIS(domain, storedObject):
	whois = pythonwhois.get_whois(domain)
	
	#Store DNS information
	for nameserver in whois["nameservers"]:
		nameserverIPv4 = singleQuery(nameserver, 'A')
		nameserverIPv6 = singleQuery(nameserver, 'AAAA')
		NSDomainElement = domainOSINTdata.domainElement (nameserver, str(nameserverIPv4[0]), str(nameserverIPv6[0]))
		storedObject.addDNS(NSDomainElement)

	#Store creation, update and expiration dates
	whois["creation_date"]
	whois["updated_date"]
	whois["expiration_date"]
	#TODO: Store this information in the object





