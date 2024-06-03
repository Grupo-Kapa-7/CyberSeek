from core.core import *
from core.Validator import *
import sys,readline
from pathlib import Path
from core.FileScan import *
from core.KasperskyOpenTIP import *
from core.VirusTotal import *
import time

class SandBox:
    def sandbox_menu():
        print(f"{c.Orange}**** Dynamic Analysis [filescan.io] ****{c.Reset}")
        print(f"""[{c.Red}1{c.Reset}] Scan an url
[{c.Red}2{c.Reset}] Scan a file (100 MB)
[{c.Red}3{c.Reset}] Get file report by task id
[{c.Red}0{c.Reset}] Back""")
        
    def check_task(task_id):
        if task_id=="0":
            return False,0
        result=False
        while True:
            time.sleep(10)
            monitor,filesize=FileScan.check_task(task_id)
            if monitor=="finished":
                print(f"Task status: {c.Orange}finished                                {c.Reset}")
                result=True
                break
            elif monitor=="scanning":
                print(f"Task status: {c.Orange} scanning... {c.Reset}                                           ",end="\r")
            elif monitor=="created":
                print(f"Task status: {c.Orange} created... {c.Reset}                                            ",end="\r")
            else:
                result=False
                break

        return result,filesize


    def main():
        while True:
            SandBox.sandbox_menu()
            option=input("👾: ")
            if option=="0":
                break
            elif option=="1":
                url=input("Enter url: ")
                value=url.replace(" ","")
                if not validator.url(value):
                    print(f"{c.Red}Invalid url!{c.Reset}")
                else:
                    task_id=FileScan.send_url(value)
                    KasperskyOpenTIP.check_url(value)
                    VirusTotal.check_url(value)
                    print(f"Running sandbox analysis, task id {c.Orange}{task_id}{c.Reset}")
                    result,filesize= SandBox.check_task(task_id)
                    if result:
                        FileScan.url_report(task_id)
                    else:
                        print(f"{c.Red}Error trying to check status for task {c.Orange}{task_id}{c.Reset}")
                        print(f"{c.Blue}Select option 3, with your task id {c.Orange}{task_id}{c.Reset}")
                    
            elif option=="2":
                filename=input("filename: ")
                file = Path(filename)
                if not file.is_file():
                    print(f"{c.Red}file {filename} not found!{c.Reset}")
                else:
                    task_id=FileScan.send_file(filename)
                    print(f"Running sandbox analysis, task id {c.Orange}{task_id}{c.Reset}")
                    if SandBox.check_task(task_id):
                        FileScan.file_report(task_id)
                    else:
                        print(f"{c.Red}Error trying to check status for task {c.Orange}{task_id}{c.Reset}")
                        print(f"{c.Blue}Select option 3, with your task id {c.Orange}{task_id}{c.Reset}")
            elif option=="3":
                task_id=input("enter task id: ")
                
                result,filesize= SandBox.check_task(task_id)
                if result and filesize>0:
                    FileScan.file_report(task_id)
                elif result and filesize==0:
                    FileScan.url_report(task_id)
                else:
                    print(f"{c.Red}Error trying to check status for task {c.Orange}{task_id}{c.Red}, try again in 1 min.{c.Reset}")
            else:
                print(f"{c.Red}invalid input!\n{c.Reset}")