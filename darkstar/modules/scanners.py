from modules.db_helper import *
from modules.vulns import Vulnerability, CVE
from modules.HIBPwned import HIBPwned
import pandas as pd
import os
import subprocess
import base64 
from colorama import Fore, Style, init
import hashlib
import threading
import re

class bbot():
    def __init__(self, target: str, org_name: str):
        self.target = target
        self.folder = f"/app/bbot_output"
        self.foldername = hashlib.md5(os.urandom(10)).hexdigest()
        self.org_name = org_name

        #? Create a directory for bbot output if not exists
        if not os.path.exists(self.folder):
            os.mkdir(self.folder)

    def vulns_to_db(self, df: pd.DataFrame) -> None:
        for index, row in df.iterrows():
            if row['Event type'] == "VULNERABILITY" or row["Event type"] == "FINDING":
                #? Get the object and store into the database as a vulnerability
                #FINDING,"{'host': 'lijn83po.nl', 'description': 'OpenID Connect Endpoint (domain: lijn83po.nl) found at https://login.windows.net/lijn83po.nl/.well-known/openid-configuration', 'url': 'https://login.windows.net/lijn83po.nl/.well-known/openid-configuration'}",194.50.112.30,oauth,0,in-scope,"Scan 6fffbee34a9624d6774bb1c6fa3adf96 seeded with DNS_NAME: lijn83po.nl --> oauth identified FINDING: OpenID Connect Endpoint for ""lijn83po.nl"" at https://login.windows.net/lijn83po.nl/.well-known/openid-configuration"
                #TODO: Command Injection vulnerability, if someone is able to alter the csv data from the bbot tool -> malicious install maybe its unlikely but need to keep in mind
                item = eval(row["Event data"])
                if isinstance(item, str):
                    item = eval(item)
                severity = "info" if row["Event type"] == "FINDING" else item.get("severity", None)
                finding_object = Vulnerability(
                    title='asm finding',
                    affected_item=item.get("url", None),
                    tool="bbot",
                    confidence=90,
                    severity=severity,
                    host=item.get("host", None),
                    poc=item.get("url", None),
                    summary=item.get("description", None)
                )
                print(f"[+] Adding to database:\n{finding_object}")
                insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)

    def hibpwned(self) -> None:
        print(f"{self.folder}/{self.foldername}/emails.txt")
        
        if not os.path.exists(f"{self.folder}/{self.foldername}/emails.txt"):
            print(f"[-] No emails file found")
            return
        hibp = HIBPwned(f"{self.folder}/{self.foldername}/emails.txt", self.org_name)
        hibp.run()

    def prep_data(self) -> pd.DataFrame:
        if os.path.exists(f"{self.folder}/{self.foldername}/output.csv"):
            #? write to DB
            df = pd.read_csv(f"{self.folder}/{self.foldername}/output.csv")
            
            #? Replace NaN with None
            df = df.where(pd.notnull(df), None)

            self.hibpwned()

            #TODO: Check if bbot found any vulns write to vulnerability class and insert to db
            self.vulns_to_db(df)          

            return df    
        else:
            print(f"{Fore.RED}[-] No output file found, Something went wrong with bbot scan{Style.RESET_ALL}")
            return pd.DataFrame()

    def passive(self) -> None:
        print(f"{Fore.GREEN}[+] Scanning {self.target} with passive bbot{Style.RESET_ALL}")

        command = ["/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,subdomain-enum,cloud-enum,email-enum,social-enum,code-enum", "-o", self.folder, "-n", self.foldername, "-y"]
        
        #? Run bbots with passive settings
        process = subprocess.run(command, capture_output=True, text=True)

        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv intot the database
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)

    def aggressive(self) -> None:
        print(f"{Fore.GREEN}[+] Scanning {self.target} with aggressive bbot{Style.RESET_ALL}")

        command = ["/root/.local/bin/bbot", "-t", self.target, "-f", "safe,passive,active,deadly,aggressive,web-thorough,subdomain-enum,cloud-enum,code-enum,affiliates", "-m", "nuclei,baddns,baddns_zone,dotnetnuke,ffuf", "--allow-deadly", "-o", self.folder, "-n", self.foldername, "-y"]

        #? Run bbot with aggressive settings
        process = subprocess.run(command, capture_output=True, text=True)

        #? place target name in the foldername
        with open(f"{self.folder}/{self.foldername}/TARGET_NAME", "w") as target_file:
            target_file.write(self.target)

        #? Store data from csv into the database
        insert_bbot_to_db(self.prep_data(), org_name=self.org_name)

class nuclei():
    def __init__(self, filename: str, org_name: str):
        self.file = filename
        self.org_name = org_name

    def scan_nuclei(self) -> None:
        keywords = ["unknown", "low", "medium", "high", "critical"]
        #nuclei_command = f"nuclei -l domains.txt -s low,medium,high,critical,unknown -et github -bs 400 -rl 4000"
        nuclei_command = f"nuclei -l {self.file} -s low,medium,high,critical,unknown -et github -bs 400 -rl 1000"
        
        process = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)  
        while True:  
            output_line = process.stdout.readline()  
            if not output_line and process.poll() is not None:  
                break  

            if output_line:     
                if any(keyword in output_line for keyword in keywords):  
                    # extract url with regex
                    url = ""
                    try:
                        url = re.search(r"(?P<url>https?://[^\s]+)", output_line).group("url")
                    except:
                        try:
                            url = re.search(r"(?P<url>http?://[^\s]+)", output_line).group("url")
                            #.group("url")
                        except:
                            #find it port based by x:443 or x:80
                            url = re.search(r"(?P<url>[^\s]+:[0-9]+)", output_line).group("url")
                            # cut off port
                            url = url.split(":")[0]

                    domain = url 
                    # replace https:// http:// www.
                    domain = domain.replace("https://", "")
                    domain = domain.replace("http://", "")
                    domain = domain.replace("www.", "")

                    epss_percentile = None  


                    # if has / in it, stop at /
                    if "/" in domain:
                        domain = domain.split("/")[0]

                    # extract cve with regex
                    cve = re.search(r"(?P<cve>CVE-[^\s]+)", output_line)
                    #print(cve)

                    # get first element of output line
                    vuln = output_line.split(" ")[0]

                    if cve:
                        cve = cve.group("cve")
                    else:
                        # strip vuln from color
                        vuln = re.sub(r'\x1b[^m]*m', '', vuln)
                        # strip vuln from [
                        vuln = vuln.split("[")[1]
                        # strip vuln from ]
                        vuln = vuln.split("]")[0]

                    vuln2 = vuln
                    before = "Vulnerability found"
                    # if the output line ends with a something inbetween []
                    # get last part of output line
                    last = output_line.split(" ")[-1]
                    # remove enters or spaces at the end
                    last = last.strip()
                    # if last part of output line starts with [
                    if last.endswith("]"):
                        before = vuln 
                        # strip last from color
                        last = re.sub(r'\x1b[^m]*m', '', last)
                        # strip last from ]
                        last = last.split("]")[0]
                        # replace vuln with last
                        vuln2 = vuln
                        vuln = last

                    exploit = False
                    epss = 0.0

                    if cve:
                        before = "CVE match found"
                        # cut off at first :
                        cve = cve.split(":")[0]
                        # cut off at first ]
                        cve = cve.split("]")[0]
                        # remove colors from cve
                        cve = re.sub(r'\x1b[^m]*m', '', cve)
                        cve_number = cve
                    else:
                        cve_number = None
                    # if unknown
                    category = ""
                    category2 = ""
                    
                    if "unknown" in output_line:
                        category = "low"
                        category2 = "unknown"
                    elif "low" in output_line:
                        category = "low"
                        category2 = "low"
                    elif "medium" in output_line:
                        category = "medium"
                        category2 = "medium"
                    elif "high" in output_line:
                        category = "high"
                        category2 = "high"
                    elif "critical" in output_line:
                        category = "critical"
                        category2 = "critical"


                    finding_object = Vulnerability(vuln, url, "nuclei", 97, category, host=domain, cve_number=cve_number, epss=epss_percentile)

                    #? add to database
                    print(f"[+] Adding to database:\n{finding_object}")
                    insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)

    #? Run the nuclei flow
    def run(self) -> None:     
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()

class nuclei_wordpress():
    def __init__(self, domains: str, org_name: str):
        self.domains = domains
        self.org_name = org_name

    def scan_nuclei(self) -> None:
        keywords = ["unknown", "low", "medium", "high", "critical"]
        #nuclei_command = f"nuclei -l domains.txt -s low,medium,high,critical,unknown -et github -bs 400 -rl 4000"
        print(f"[+] Running Nuclei wordpress")
        
        nuclei_command = f"nuclei -u \"{self.domains}\" -s low,medium,high,critical,unknown -t github -bs 400 -rl 4000"
        print(nuclei_command)
        process = subprocess.Popen(nuclei_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, bufsize=1, universal_newlines=True)  
        while True:  
            output_line = process.stdout.readline()  
            if not output_line and process.poll() is not None:  
                break  

            if output_line:     
                if any(keyword in output_line for keyword in keywords):  
                    print(f"Output Line: {output_line}")
                    # extract url with regex
                    url = ""
                    try:
                        url = re.search(r"(?P<url>https?://[^\s]+)", output_line).group("url")
                    except:
                        try:
                            url = re.search(r"(?P<url>http?://[^\s]+)", output_line).group("url")
                            #.group("url")
                        except:
                            #find it port based by x:443 or x:80
                            url = re.search(r"(?P<url>[^\s]+:[0-9]+)", output_line).group("url")
                            # cut off port
                            url = url.split(":")[0]

                    domain = url 
                    # replace https:// http:// www.
                    domain = domain.replace("https://", "")
                    domain = domain.replace("http://", "")
                    domain = domain.replace("www.", "")

                    epss_percentile = None  


                    # if has / in it, stop at /
                    if "/" in domain:
                        domain = domain.split("/")[0]

                    # extract cve with regex
                    cve = re.search(r"(?P<cve>CVE-[^\s]+)", output_line)
                    #print(cve)

                    # get first element of output line
                    vuln = output_line.split(" ")[0]
                    print(f"Raw vuln: {vuln}")

                    pattern = re.compile(r'\[(?P<title>.*?)(?=-[0-9a-fA-F]+:version)\-[0-9a-fA-F]+:version\]')
                    vuln = pattern.findall(vuln)
                    
                    if cve:
                        cve = vuln
                    
                    vuln2 = vuln
                    before = "Vulnerability found"
                    # if the output line ends with a something inbetween []
                    # get last part of output line
                    last = output_line.split(" ")[-1]
                    # remove enters or spaces at the end
                    last = last.strip()
                    # if last part of output line starts with [
                    if last.endswith("]"):
                        before = vuln 
                        # strip last from color
                        last = re.sub(r'\x1b[^m]*m', '', last)
                        # strip last from ]
                        last = last.split("]")[0]
                        # replace vuln with last
                        vuln2 = vuln
                        vuln = last

                    exploit = False
                    epss = 0.0

                    if cve:
                        before = "CVE match found"
                        # cut off at first :
                        cve = cve.split(":")[0]
                        # cut off at first ]
                        cve = cve.split("]")[0]
                        # remove colors from cve
                        cve = re.sub(r'\x1b[^m]*m', '', cve)
                        cve_number = cve
                    else:
                        cve_number = None
                    # if unknown
                    category = ""
                    category2 = ""
                    
                    if "unknown" in output_line:
                        category = "low"
                        category2 = "unknown"
                    elif "low" in output_line:
                        category = "low"
                        category2 = "low"
                    elif "medium" in output_line:
                        category = "medium"
                        category2 = "medium"
                    elif "high" in output_line:
                        category = "high"
                        category2 = "high"
                    elif "critical" in output_line:
                        category = "critical"
                        category2 = "critical"

                    print(f"Vuln: {vuln}, Vuln2: {vuln2}")
                    finding_object = Vulnerability(vuln2, url, "nuclei_wordpress", 97, category, host=domain, cve_number=cve_number, epss=epss_percentile)

                    #? add to database
                    print(f"[+] Adding to database:\n{finding_object}")
                    insert_vulnerability_to_database(vuln=finding_object, org_name=self.org_name)

    #? Run the nuclei flow
    def run(self) -> None:     
        thread = threading.Thread(target=self.scan_nuclei)
        thread.start()


class nuclie_network():
    def __init__(self, worker):
        self.worker = worker
    
