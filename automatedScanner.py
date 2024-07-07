import os 
from sys import stderr 
import errno
import sh 
import pyfiglet 
import subprocess 
import nmap
import socket 
from datetime import datetime 
from wapitiCore import Wapiti
import json 
import requests 
from zapv2 import ZAPv2
import time 



ascii_banner = pyfiglet.figlet_format("AUTOMATED VAPT") 
print(ascii_banner) 
textfile = input("enetr name of your file here: ")
file1 = str(os.read(textfile, "rt"))
file_ext = os.path.splitext(file1)
if file_ext == ".txt":
    def chechPorts():
        #check if port 80 and 445 are open and curl header 
        headers_and_ports = #all the required information 
        return headers_and_ports
    if file1 != "":
        for i in range(len(file1)):
                

            class scan_with_nmap:
                def __init__(self, file1):
                    #file 1 contains p addresses 
                    #file 2
                    self.file1
                    self.File2
                    pass
                def _iter__(self):
                    return self
                def _next_(self,):
                    pass 
                def scan(self, file1):
                    #code for nmap to scaan the ip address 
                    File2 = #output of namp scan
                    return File2
                    pass 
                def Cve_Cwe(self, File2):
                    pass 
                def output(self):
                    info = #cve ratings and stuff
                    print(info)
    else:
        print("empty file")
elif file_ext == ".js":
    collection_file = os.open(textfile, "rt")
    collection_file1 = os.read(collection_file)
    class collection_scan_with_newman:
        def __init__(self, collection_file1)-> None :
            self.collection1 = collection_file1 
            self.collecton_results 
        def extract_Urls(self, collection1)
            with os.open(collection1, "rb") as js_collection
            collection2 = json.load(js_collection)
            urls =[]
            for item in collection2['item']:
                if 'request'in item:
                 urls.append(item['request']['url']['raw'])
            return urls
        def collect_scan(self, urls):
            #subprocess to open newman and proxy through wapiti3 results to collecton results 
           for url in urls:
                print(f'scanning{url}') 
                target_url = url
                wapiti_scan = Wapiti(target_url)
                wapiti_scan.crawl()
                wapiti_scan.audit()
                collection_results = wapiti_scan.generate_report(format='json')
                print(collection_results)
        def owasp_zap(self, urls):
            apikey = input("enter your api key: ")
            zap = ZAPv2(apikey)
            for url in urls:
                print(f'scanning{url} with owasp')
                zap.urlopen(url)

                # Start spidering the target
                print("Starting spider...")
                scan_id = zap.spider.scan(url)
                while int(zap.spider.status(scan_id)) < 100:
                    print(f"Spider progress: {zap.spider.status(scan_id)}%")
                    time.sleep(2)
                print("Spider completed")

                # Start active scanning
                print("Starting active scan...")
                scan_id = zap.ascan.scan(url)
                while int(zap.ascan.status(scan_id)) < 100:
                    print(f"Scan progress: {zap.ascan.status(scan_id)}%")
                    time.sleep(2)
                print("Active scan completed")

                # Print out the alerts
                print("Alerts:")
                alerts = zap.core.alerts(baseurl=url)
                for alert in alerts:
                    print(alert)
        def getCve_and_severity(self, alerts):
                    #get cve ratng 
                    pass

                

else:
    print("""Wrong extension.
          please use .js or .txt. 
          More extensions coming soon..""")


try: 
    scan1 = scan()
except BaseException as e:
    print("somebase exeeption", os.strerror(e.errno))
finally:
    print("scan done")

#https://chatgpt.com/share/cb18781c-5bd9-4e9c-9722-d9a2ed4d398a