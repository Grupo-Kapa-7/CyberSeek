import requests
from core.core import *
from fake_useragent import UserAgent
from tabulate import tabulate

class MXToolBox:
    def blacklist_check(value):
        try:
            agent=UserAgent().random
            print(f"\nChecking domain/ip {c.Orange}{value}{c.Reset} on MXToolBox [blacklist] ...")
            headers={"User-Agent":agent,"TempAuthorization":"27eea1cd-e644-4b7b-bebe-38010f55dab3"}
            response=requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={value}&resultindext=1&disableRhsbl=true&format=1",headers=headers)
            if response.status_code==200:
                data = response.json()
                if data['ResultDS']:
                    ResultDS=data['ResultDS']['SubActions']

                    headers=["Name","Result"]
                    jsondata=[]
                    for x in ResultDS:
                        verdit=x['Status']
                        result=""
                        if verdit=="0":
                            result=f"{c.Green}Clean{c.Reset}"
                        elif verdit=="1":
                            result=f"{c.Yellow}TimeOut{c.Reset}"
                        else:
                            result=f"{c.Red}Listed{c.Reset}"

                        name=x['Name']
                        row=[name,result]
                        jsondata.append(row)

                    print(tabulate(jsondata, headers, tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            print(f"{c.Red}Error on domain/ip reputation process for MXToolBox!{c.Reset}")
            pass

    def spf_check(domain):
        try:
            agent=UserAgent().random
            print(f"\nChecking spf for domain {c.Orange}{domain}{c.Reset} on MXToolBox...")
            headers={"User-Agent":agent,"TempAuthorization":"27eea1cd-e644-4b7b-bebe-38010f55dab3"}
            response=requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=spf&argument={domain}&resultindext=2&disableRhsbl=true&format=1",headers=headers)

            if response.status_code==200:
                data = response.json()
                if data['ResultDS']:
                    ResultDS=data['ResultDS']['SubActions']
                    spf_description=data['ResultDS']['Information'][0]['Description']

                    headers=["Module","Result"]
                    jsondata=[]
                    for x in ResultDS:
                       verdit=x['Status']
                       result=""

                       if verdit=="0":
                           result=f"{c.Green}{x['Response']}{c.Reset}"
                       elif verdit=="1":
                           result=f"{c.Yellow}{x['Response']}{c.Reset}"
                       else:
                           result=f"{c.Red}{x['Response']}{c.Reset}"

                       name=x['Name']
                       row=[name,result]
                       jsondata.append(row)

                    print(f"\nSPF: {c.Orange}{spf_description}{c.Reset}\n")
                    print(tabulate(jsondata, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            print(f"{c.Red}Error on spf check process for MXToolBox!{c.Reset}")
            pass

    # def whois_lookup(value):
    #     try:
    #         agent=UserAgent().random
    #         print(f"\nWhois lookup for domain/ip {c.Orange}{value}{c.Reset} on MXToolBox...")
    #         headers={"User-Agent":agent,"TempAuthorization":"27eea1cd-e644-4b7b-bebe-38010f55dab3"}
    #         response=requests.get(f"https://mxtoolbox.com/api/v1/Lookup?command=whois&argument={value}&resultindext=2&disableRhsbl=true&format=1",headers=headers)

    #         if response.status_code==200:
    #             data = response.json()
    #             if data['Model']:
    #                 ParsedItems=data['Model']['ParsedItems']
    #                 headers=["Module","Result"]
    #                 jsondata=[]

    #                 for x in ParsedItems:
    #                    name=x['Name']
    #                    result=f"{c.Green}{x['Value']}{c.Reset}"
    #                    row=[name,result]
    #                    jsondata.append(row)

    #                 print(tabulate(jsondata, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
    #     except:
    #         print(f"{c.Red}Error on whois lookup  process for MXToolBox!{c.Reset}")
    #         pass