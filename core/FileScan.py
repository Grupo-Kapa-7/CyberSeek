import requests
from tabulate import tabulate
from core.core import *
import time

class FileScan:
    def send_file(filename):
        try:
            url = 'https://www.filescan.io/api/scan/file'
            with open(filename, 'rb') as file:
                res = requests.post(url, files={'file': file})  
            return res.json()["flow_id"]
        except:
            return "0"
        
    def send_url(requested_url):
        try:
            url = 'https://www.filescan.io/api/scan/url'
            data = {'url': requested_url}
            res = requests.post(url, data=data)
            return res.json()["flow_id"]
        except:
            return "0"

    def verdict(data):
        try:
            jsonDataVerdict=[]
            print(f"{c.Orange}Checking verdict...{c.Reset}")
            row = data["finalVerdict"]["verdict"]

            if row=="MALICIOUS":
                verdict = ["Verdict",f"{c.Red}{row}{c.Reset}"]
            elif row=="SUSPICIOUS":
                verdict = ["Verdict",f"{c.Orange}{row}{c.Reset}"]
            elif row=="LIKELY_MALICIOUS":
                verdict = ["Verdict",f"{c.Yellow}{row}{c.Reset}"]
            else:
                verdict = ["Verdict",f"{c.DarkGrey}{row}{c.Reset}"]

            name = ["Name",data["file"]["name"]]
            hash = ["Hash",data["file"]["hash"]]
            type = ["Type",data["file"]["type"]]

            jsonDataVerdict.append(verdict)
            jsonDataVerdict.append(name)
            jsonDataVerdict.append(hash)
            jsonDataVerdict.append(type)
            headers=["Module","Results"]
            print(tabulate(jsonDataVerdict, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            pass

    def signals(data):
        try:
            jsonDataSignals=[]
            jsonDataSignals2=[]
            allSignalGroups = data["allSignalGroups"]
            for signal in allSignalGroups:
                row =signal
                identifier=f'{c.Green}{row["identifier"]}{c.Reset}'
                description=row["description"]

                if row["verdict"]["verdict"]=="INFORMATIONAL":
                    verdict=f'{c.Blue}{row["verdict"]["verdict"]}{c.Reset}'
                elif row["verdict"]["verdict"]=="SUSPICIOUS":
                    verdict=f'{c.Yellow}{row["verdict"]["verdict"]}{c.Reset}'
                elif row["verdict"]["verdict"]=="LIKELY_MALICIOUS":
                    verdict=f'{c.Orange}{row["verdict"]["verdict"]}{c.Reset}'
                elif row["verdict"]["verdict"]=="MALICIOUS":
                    verdict=f'{c.Red}{row["verdict"]["verdict"]}{c.Reset}'
                else:
                    verdict=f'{c.DarkGrey}{row["verdict"]["verdict"]}{c.Reset}'

                signalReadable=row["signals"][0]["signalReadable"]

                jsonDataSignals.append([identifier,description,verdict])
                jsonDataSignals2.append([signalReadable,verdict])
            
            headers=["#","Identifier","Description","Verdict"]
            print(tabulate(jsonDataSignals, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

            print(f"{c.Orange}Checking activity...{c.Reset}")
            headers=["#","Activity","Verdict"]
            print(tabulate(jsonDataSignals2, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))

        except:
            pass

    def MITRE(data):
        try:
            jsonDataMitre=[]
            allSignalGroups = data["allSignalGroups"]
            print(f"{c.Orange}Checking MITRE Techniques...{c.Reset}")
            for signal in allSignalGroups:
                row =signal
                try:
                    allMitreTechniques=row["allMitreTechniques"]
                    for technique in allMitreTechniques:
                        row2=technique
                        id=row2["ID"]
                        relatedTacticId=row2["relatedTactic"]["ID"]
                        relatedTacticName=row2["relatedTactic"]["name"]
                        name=row2["name"]
                        jsonDataMitre.append([id,relatedTacticId,relatedTacticName,name])
                except:
                    pass
            
            headers=["#","MITRE ID","Tactic ID","Name","Description"]
            print(tabulate(jsonDataMitre, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            pass

    def domains_resolution(data):
        try:
            jsonDataDomains=[]
            for x in data:
                try:
                    domainResolveResults=data[x]["domainResolveResults"]

                    for item in domainResolveResults:
                        domain_results=item
                        domain=f'{c.Green}{domain_results["resource"]["data"]}{c.Reset}'
                        ip=domain_results["geoData"]["ip"]
                        country_name=domain_results["geoData"]["country_name"]
                        city=domain_results["geoData"]["city"]
                        jsonDataDomains.append([domain,ip,country_name,city])
                except:
                    pass
            print(f"{c.Orange}Checking domains resolutions...{c.Reset}")
            headers=["#","Domain","IP","Country","City"]
            print(tabulate(jsonDataDomains, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            pass

    def extracted_urls(data):
        try:
            jsonDataUrls=[]
            for x in data:
                try:
                    extractedUrls=data[x]["extractedUrls"]
                    for item in extractedUrls:
                        urls=item["references"]
                        for url in urls:
                            jsonDataUrls.append([url["data"]])
                except:
                    pass
            print(f"{c.Orange}Checking extracted urls...{c.Reset}")
            headers=["#","url"]
            print(tabulate(jsonDataUrls, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
        except:
            pass

    def strings(data):
        try:
            extracted_strings=""
            for x in data:
                try:
                    extractedStrings=data[x]["strings"]
                    for item in extractedStrings:
                        strings2= item["references"]
                        for y in strings2:
                            extracted_strings+=y["str"]+"\n"
                except:
                    pass
            print(f"{c.Orange}Checking extracted strings...{c.Reset}")

            with open("strings.txt","w") as f:
                f.write(extracted_strings)

            print(f"{c.Green}Strings data was save into the file strings.txt!{c.Reset}")

        except:
            pass

    def emulation_data(data):
        try:
            
            print(f"{c.Orange}Checking for emulation data...{c.Reset}")
            for x in data:
                try:
                    emulationData=data[x]["emulationData"]
                    
                    for item in emulationData:
                        jsonEmulationData=[]
                        row=item
                        jsonEmulationData.append(["Action",f'{c.Green}{row["action"]}{c.Reset}'])
                        additionalInformation=row["additionalInformation"]
                        for y in additionalInformation:
                            jsonEmulationData.append([y,additionalInformation[y]])

                        headers=["#","name","value"]
                        print(tabulate(jsonEmulationData, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
                except:
                    pass
            
            
        except:
            pass

    def file_report(task_id):
        try:
            url=f"https://www.filescan.io/api/scan/{task_id}/report?sorting=allSignalGroups(description%3Aasc%2CallMitreTechniques%3Adesc%2CaverageSignalStrength%3Adesc)s"
            res = requests.get(url)

            if res.status_code==200:
                data=res.json()["reports"]
                for x in data:
                    try:
                        verdict= data[x]
                        FileScan.verdict(verdict)
                        FileScan.signals(verdict)
                        FileScan.MITRE(verdict)

                    except:
                        pass

            time.sleep(3)
            url=f"https://www.filescan.io/api/scan/{task_id}/report?filter=dr:domainResolveResults&filter=f:extractedUrls&filter=f:emulationData&filter=f:strings"
            res = requests.get(url)

            if res.status_code==200:
                data=res.json()["reports"]
                for x in data:
                    data2=data[x]["resources"]
                    FileScan.domains_resolution(data2)
                    FileScan.extracted_urls(data2)
                    FileScan.emulation_data(data2)
                    FileScan.strings(data2)
                    
        except:
            pass

    def url_report(task_id):
        try: 

            url=f"https://www.filescan.io/api/scan/{task_id}/report?sorting=allSignalGroups(description%3Aasc%2CallMitreTechniques%3Adesc%2CaverageSignalStrength%3Adesc)s"
            res = requests.get(url)

            if res.status_code==200:
                data=res.json()["reports"]
                for x in data:
                    try:
                        verdict= data[x]
                        FileScan.verdict(verdict)
                        FileScan.signals(verdict)

                    except:
                        pass

            time.sleep(3)
            url=f"https://www.filescan.io/api/scan/{task_id}/report?filter=f:renderResults"
            res = requests.get(url)

            if res.status_code==200:
                data=res.json()["reports"]
                
                for x in data:
                    try:
                        results=data[x]["resources"]
                        jsonData=[]
                        for y in results:
                            data2=results[y]["renderResults"]["renderResults"]
                            for z in data2:
                                urlRenderData = z["urlRenderData"]["result"]["data"]["requests"]
                                for r in urlRenderData:
                                    try:
                                        
                                        row=r
                                        type=row["response"]["type"]
                                        remoteIPAddress=f'{c.Orange}{row["response"]["response"]["remoteIPAddress"]}{c.Reset}'
                                        status=row["response"]["response"]["status"]
                                        requested_url=row["response"]["response"]["url"]
                                        country=row["response"]["geoip"]["country"]
                                        method=f'{c.Green}{row["request"]["request"]["method"]}{c.Reset}'
                                        jsonData.append([method,remoteIPAddress,status,country,type,requested_url[:110]])
                                    except:
                                        pass

                        headers=["#","Method","IP","Status","Country","Type","Url"]
                        print(tabulate(jsonData, headers,  tablefmt="grid",numalign="left",showindex=True,floatfmt=".2f"))
                                    
                    except:
                        pass
                    
                
        except:
            pass

    def check_task(task_id):
        try:
            url=f"https://www.filescan.io/api/scan/{task_id}/report?filter=general"
            res = requests.get(url)
            return res.json()["state"],res.json()["fileSize"]
        except:
            return "error",0