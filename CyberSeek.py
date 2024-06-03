#!/usr/bin/env python3

import socket
import sys,readline
from core.core import *
from core.MXToolBox import *
from core.KasperskyOpenTIP import *
from core.VirusTotal import *
from core.AlienVault import *
from core.Shodan import *
from core.DNSInfo import *
from core.Validator import *
from tabulate import tabulate
from core.MalwareBazaar import *
from core.SandBox import *

Banner.CyberSeekBanner()

def MainMenu():
    print(f"""[{c.Red}1{c.Reset} ] IP reputation
[{c.Red}2{c.Reset} ] Domain reputation
[{c.Red}3{c.Reset} ] Hostname reputation
[{c.Red}4{c.Reset} ] Url analysis
[{c.Red}5{c.Reset} ] File analysis (md5/sha256/sha512)
[{c.Red}6{c.Reset} ] Blacklist check
[{c.Red}7{c.Reset} ] Whois info
[{c.Red}8{c.Reset} ] SPF check
[{c.Red}9{c.Reset} ] DNS info
[{c.Red}10{c.Reset}] Sandbox Analysis
[{c.Red}0{c.Reset} ] Exit""")
    

def get_dns_resolution_ip(ip):
    virustotal_result=VirusTotal.check_resolution_ip(ip)
    alienvault_result=AlienVault.check_resolution_ip(ip)
    shodan_result=Shodan.check_resolution_ip(ip)

    results=[]
    try:
        for x in virustotal_result:
            results.append(x)
    except:
        pass
   
    try:
        for x in alienvault_result:
            results.append(x)
    except:
        pass
    
    try:
        for x in shodan_result:
            results.append(x)
    except:
        pass
    

    header=["Engine","Hostname"]
    print(tabulate(results, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

def get_dns_resolution_hostname(hostname):
    virustotal_result=VirusTotal.check_resolution_ip(ip)
    alienvault_result=AlienVault.check_resolution_ip(ip)
    shodan_result=Shodan.check_resolution_ip(ip)

    results=[]
    for x in virustotal_result:
        results.append(x)
    for x in alienvault_result:
        results.append(x)
    for x in shodan_result:
        results.append(x)

    header=["Engine","Hostname"]
    print(tabulate(results, header,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

while True:
    #os.system('cls' if os.name == 'nt' else 'clear')
    MainMenu()
    option=input("👾: ")

    if option=="0":
        sys.exit()
    elif option=="1":#IP reputation
        ip=input("Enter IP: ")
        value=ip.replace(" ","")
        if not validator.ip_address(value):
            print(f"{c.Red}Invalid IP!{c.Reset}")
        else:
            KasperskyOpenTIP.check_ip(value)
            VirusTotal.check_ip(value)
            get_dns_resolution_ip(value)
            Shodan.check_ports_vuls(value)

    elif option=="2": #Domain reputation
        domain=input("Enter domain: ")
        value=domain.replace(" ","")
        if not validator.domain(value):
            print(f"{c.Red}Invalid domain!{c.Reset}")
        else:
            KasperskyOpenTIP.check_domain(value)
            VirusTotal.check_domain(value)

    elif option=="3": #Hostname reputation
        hostname=input("Enter hostname: ")
        value=hostname.replace(" ","")
        if not validator.hostname(value):
            print(f"{c.Red}Invalid hostname!{c.Reset}")
        else:
            KasperskyOpenTIP.check_domain(value)
            VirusTotal.check_hostname(value)
            Shodan.check_ports_vuls(value)

    elif option=="4": #Url Analisys
        url=input("Enter url: ")
        value=url.replace(" ","")
        if not validator.url(value):
            print(f"{c.Red}Invalid url!{c.Reset}")
        else:
            KasperskyOpenTIP.check_url(value)
            VirusTotal.check_url(value)

    elif option=="5": #File Analisys 
        hash=input("Enter hash (md5/sha256/sha512): ")
        value=hash.replace(" ","")
        if not validator.hash(value):
            pass
        else:
            KasperskyOpenTIP.check_file(value)
            VirusTotal.check_file(value)
            VirusTotal.check_contacted_urls(value)
            VirusTotal.check_contacted_domains(value)
            MalwareBazaar.hash_lookup(value)

    elif option=="6": #Blacklist check
        domain_ip=input("Enter domain/ip: ")
        value=domain_ip.replace(" ","")
        if validator.ip_address(value) or validator.domain(value):
            MXToolBox.blacklist_check(value)
        else:
            print(f"{c.Red}Invalid domain or ip!{c.Reset}")
            

    elif option=="7": #Whois Lookup
        domain_or_ip=input("Enter domain/ip: ")
        value=domain_or_ip.replace(" ","")
        if validator.ip_address(value):
            KasperskyOpenTIP.ip_whois(value)
        elif validator.domain(value):
            KasperskyOpenTIP.domain_whois(value)
        else:
            print(f"{c.Red}Invalid domain or ip!{c.Reset}")

    elif option=="8": #SPF Check
        domain=input("Enter domain: ")
        value=domain.replace(" ","")
        if not validator.domain(value):
            print(f"{c.Red}Invalid domain!{c.Reset}")
        else:
            MXToolBox.spf_check(domain)
            
        
    elif option=="9":
        hostname_domain=input("Enter hostname/domain: ")
        value=hostname_domain.replace(" ","")
        if validator.domain(value) or validator.hostname(hostname_domain):
            DNSInformation.main(value)
        else:
            print(f"{c.Red}Invalid domain!{c.Reset}")
    
    elif option=="10":
        SandBox.main()
    else:
        print(f"{c.Red}invalid input!\n{c.Reset}")
