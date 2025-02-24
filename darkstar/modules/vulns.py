import subprocess
import requests
import pandas as pd
import datetime


class CVE:  
    def __init__(self, cve, cvss=None, summary=None, cwe=None, references=None, epss=None, capec=None, solution=None, impact=None, access=None, age=None, pocs=None, kev=None):  
        self.cve = cve  
        self.cvss = cvss  
        self.epss = epss  
        self.summary = summary   
        self.cwe = cwe  
        self.references = references  
        self.capec = capec
        self.solution = solution
        self.impact = impact 
        self.access = access
        self.age = age
        self.pocs = pocs
        self.kev = kev

    def search_epss_by_cve(cve: str) -> float:
        #? https://www.first.org/epss/data_stats
        command = ["c_scripts/search_epss", 'datasets/epss_scores-current.csv', cve]
        result = subprocess.run(command, capture_output=True, text=True)
        try:
            return float(result.stdout)
        except:
            return 'Unknown'

    def __str__(self):
        return f"{self.cve} | {self.cvss} | {self.epss} | {self.summary} | {self.cwe} | {self.references} | {self.capec} | {self.solution} | {self.impact} | {self.access} | {self.age} | {self.pocs} | {self.kev}"


class Vulnerability():
    def __init__(self, title, affected_item, tool, confidence, severity, host,
                 cve_number="", summary="", impact="", solution="", poc="",
                 references="", epss=None, cvss=None, cwe="", capec=""):
        self.title = title
        self.affected_item = affected_item
        self.tool = tool
        self.confidence = confidence
        self.severity = severity
        self.host = host

        # Use truthiness to decide whether to attempt CVE enrichment.
        if cve_number:  # This evaluates to False for an empty string.
            enriched = self.cve_enricher(cve_number)
            if enriched:
                self.cve = enriched
            else:
                # Optionally, you can set non-CVE attributes here as well
                self.summary = summary
                self.impact = impact
                self.solution = solution
                self.poc = poc
                self.references = references
                self.epss = epss
                self.cvss = cvss
                self.cwe = cwe
                self.capec = capec
        else:
            # No valid CVE provided: assign non-CVE attributes.
            self.summary = summary
            self.impact = impact
            self.solution = solution
            self.poc = poc
            self.references = references
            self.epss = epss
            self.cvss = cvss
            self.cwe = cwe
            self.capec = capec

    def cve_enricher(self, cve_number: str) -> CVE:            
        #? Get the epss score for the cve
        epss_percentile = CVE.search_epss_by_cve(cve_number)

        #? Check CISA kev
        kev = False
        cisa_kev_data = pd.read_csv("datasets/known_exploited_vulnerabilities.csv")
        if cve_number in cisa_kev_data['cveID'].values:
            kev = True
        
        #? Get more cve data about the CVE
        response = requests.get(f"https://cve.circl.lu/api/cve/{cve_number}")
        if response.status_code == 200 and response.json():
            #? Extract data from the response
            solution = response.json().get("solution", None)
            impact = response.json().get("impact", None)
            access = response.json().get("access", None)
            references = response.json().get("references", None)
            age_in_days = response.json().get("Published", None)
            cvss = response.json().get("cvss", None)
            cwe = response.json().get("cwe", None)
            capec = response.json().get("capec", None)
            summary = response.json().get("summary", None)
            
            #? Calculate the age of the CVE
            if age_in_days is not None:
                age_in_days = (datetime.datetime.now() - datetime.datetime.strptime(age_in_days, "%Y-%m-%dT%H:%M:%S")).days
            
            #? Create a CVE object
            cve_object = CVE(cve=cve_number, cvss=cvss, epss=epss_percentile, summary=summary, cwe=cwe, references=references, capec=capec, solution=solution, impact=impact, access=access, age=age_in_days, pocs=None, kev=kev)
            return cve_object
        else:
            return None
