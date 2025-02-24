import subprocess
import threading
import xml.etree.ElementTree as ET
from datetime import datetime
import requests
import json
import time
import netaddr
from modules.vulns import Vulnerability
from modules.db_helper import insert_vulnerability_to_database
from modules.config import OPENVAS_USER, OPENVAS_PASSWORD

class openvas():
    def __init__(self, targets, org_name):
        # Removed dependency on self.worker
        # You might want to keep a local list for your vulnerabilities
        self.vulnerabilities = []  
        self.queue_reportIDs = []
        self.queue_scan_names = []
        self.queue_report_location = []
        self.ips = targets
        self.username = OPENVAS_USER
        self.password = OPENVAS_PASSWORD
        self.scan_name = ""
        self.command_prefix = '' 
        self.alive_test = 'ICMP, TCP-ACK Service &amp; ARP Ping'
        self.scanConfigID = "daba56c8-73ec-11df-a475-002264764cea"  # Full and very deep ultimate
        self.formatID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        self.org_name = org_name
    
    def get_report(self, reportID, report_location):
        command = f'{self.command_prefix} "<get_reports report_id=\'{reportID}\' filter=\'apply_overrides=0 levels=hml min_qod=50 first=1 rows=1000 sort=name ignore_pagination=1\' details=\'1\' format_id=\'{self.formatID}\'/>"'
        response = requests.post('http://automatic-propagation-gvmd-1:5000/get_report',
                                 json={'command': command})
        report_data = response.json()['message'].strip()
 
        with open(report_location, 'w') as f:
            f.write(report_data)
    
    def create_target(self):
        self.report_location = f"/tmp/report_openvas_{datetime.now().strftime('%Y%m%d%H%M%S')}.xml"
        self.scan_name = f"Darkstar-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.queue_scan_names.append(self.scan_name)
        self.queue_report_location.append(self.report_location)
        command = f'{self.command_prefix} "<CREATE_TARGET><name>{self.scan_name}</name><hosts>{self.ip}</hosts><alive_tests>{self.alive_test}</alive_tests><port_range>1-65535</port_range></CREATE_TARGET>"'
        response = requests.post('http://automatic-propagation-gvmd-1:5000/create_target',
                                 json={'command': command})
        self.targetID = response.json()['message']
        
    def create_task(self):
        command = f'{self.command_prefix} \'<CREATE_TASK><name>{self.scan_name}</name><Comment>Openvas Scan on {self.ip}</Comment><target id="{self.targetID}" /><config id="{self.scanConfigID}" /></CREATE_TASK>\''
        response = requests.post('http://automatic-propagation-gvmd-1:5000/create_task',
                                 json={'command': command})
        self.taskID = response.json()['message']
    
    def run_task(self):
        command = f'{self.command_prefix} \'<start_task task_id="{self.taskID}"/>\''
        response = requests.post('http://automatic-propagation-gvmd-1:5000/run_task',
                                 json={'command': command})
        self.reportID = response.json()['message']
        self.queue_reportIDs.append(self.reportID)
    
    def check_if_finished(self, reportID):
        command_running = f'{self.command_prefix} "<get_reports report_id=\'{reportID}\' format_id=\'{self.formatID}\'/>" | xml2 | grep \'progress\' | cut -d \'=\' -f2'
        isRunningTask = requests.post('http://automatic-propagation-gvmd-1:5000/check_if_finished',
                                        json={'command': command_running})

        command_completed = f'{self.command_prefix} "<get_reports report_id=\'{reportID}\' format_id=\'{self.formatID}\'/>" | xml2 | grep \'scan_run_status\' | cut -d \'=\' -f2'
        isCompletedTask = requests.post('http://automatic-propagation-gvmd-1:5000/check_if_finished',
                                        json={'command': command_completed})

        print("isCompletedTask")
        print(isCompletedTask.json()['message'].strip())
        if isCompletedTask.json()['message'].strip() == 'Done': 
            print("Scan dOne")
            return True
        elif isCompletedTask.json()['message'].strip() == 'Running':
            print(f"OpenVAS 🌿 -> Running: {isRunningTask.json()['message'].strip()}%")
            return False
        else:  
            return False
    
    def wait_for_scan(self):
        while self.queue_scan_names:
            print(f"Current Queue List: {self.queue_scan_names}")
            new_queue_scan_names = []
            new_queue_reportIDs = []
            new_queue_report_locations = []
            
            for scan, report_id, report_location in zip(self.queue_scan_names,
                                                        self.queue_reportIDs,
                                                        self.queue_report_location):
                done = self.check_if_finished(reportID=report_id)
                print(done, scan)
                if done:
                    self.get_report(reportID=report_id, report_location=report_location)
                    self.process_findings(report_location=report_location)
                else:
                    # Keep scans that are not done
                    new_queue_scan_names.append(scan)
                    new_queue_reportIDs.append(report_id)
                    new_queue_report_locations.append(report_location)
            
            # Replace the old queues with the updated ones
            self.queue_scan_names = new_queue_scan_names
            self.queue_reportIDs = new_queue_reportIDs
            self.queue_report_location = new_queue_report_locations
            
            time.sleep(60)

    
    def process_findings(self, report_location) -> None:
        print(f"Processing findings for report: {report_location}")
        tree = ET.parse(report_location)
        root = tree.getroot()
    
        # Process each <result> element
        for result in root.findall('.//result'):
            try:
                name = result.find('name').text
            except Exception:
                continue
    
            # Skip known false positives
            if any(skip in name for skip in [
                "httpOnly", "Certificate Expired", "Weak Encryption",
                "Missing `secure`", "VNC Server Unencrypted",
                "Weak Cipher", "Vulnerable Cipher"
            ]):
                continue
    
            nvt = result.find('nvt')
            try:
                cve = nvt.find('cve').text  # May be "NOCVE"
            except Exception:
                cve = "NOCVE"
    
            # Default values
            exploit = False
            epss = 0.0
    
            port = result.find('port').text
            threat = result.find('threat').text
            severity = result.find('severity').text  # This is used later as cvss info if needed
            poc2 = result.find('description').text
            endsolution = ""
    
            # If a valid CVE is provided, check EPSs from FIRST
            if cve != "NOCVE":
                response_epss = requests.get(f"https://api.first.org/data/v1/epss?cve={cve}")
                if response_epss.status_code == 200:
                    data = response_epss.json().get("data", [])
                    if data:
                        epss = float(data[0].get("percentile", 0))
                        if epss >= 0.65:
                            exploit = True
    
            host_ip = result.find('host').text
            qod = result.find('qod')
            qod_value = qod.find('value').text  # Confidence (as a string)
    
            # Create a Vulnerability object using the provided class.
            # If a CVE is available, let the vulnerability auto-enrich by passing cve_number.
            if cve != "NOCVE":
                vuln = Vulnerability(
                    title=name,
                    affected_item=host_ip,
                    tool="OpenVAS",
                    confidence=int(qod_value),
                    severity=severity,
                    host=host_ip,
                    cve_number=cve
                )
            else:
                # When there is no CVE, include extra information directly.
                vuln = Vulnerability(
                    title=name,
                    affected_item=host_ip,
                    tool="OpenVAS",
                    confidence=int(qod_value),
                    severity=severity,
                    host=host_ip,
                    summary=poc2,
                    impact=threat,
                    solution=endsolution,
                    poc=poc2,
                    cvss=severity,
                    epss=epss
                )
    
            # For demonstration, print the vulnerability object (the __str__ method from CVE is available on vuln.cve)
            print(f"Found vulnerability: {vuln.title} on {vuln.affected_item}")
    
            # Finally, add the vulnerability to our local list
            self.vulnerabilities.append(vuln)
        
        for vuln in self.vulnerabilities:
            insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)
    
    def split_cidr(self, cidr):
        net = netaddr.IPNetwork(cidr)
        if net.prefixlen < 20:
            return [str(subnet) for subnet in net.subnet(20)]
        else:
            return [str(net)]
    
    def run(self):
        self.command_prefix = (f'gosu gvmd gvm-cli --gmp-username {self.username} '
                               f'--gmp-password \'{self.password}\'  socket '
                               f'--socketpath /run/gvmd/gvmd.sock --xml')
    
        target_list = []
        if isinstance(self.ips, str):
            ip_list = self.ips.split(' ')
            for ip in ip_list:
                if '/' not in ip:
                    target_list.append(ip)
                else:
                    target_list.extend(self.split_cidr(ip))
        else:
            for ip in self.ips:
                if '/' not in ip:
                    target_list.append(ip)
                else:
                    target_list.extend(self.split_cidr(ip))
    
        for target in target_list:
            self.ip = target
            self.create_target()
            self.create_task()
            self.run_task()
            time.sleep(3)

        threading.Thread(target=self.wait_for_scan).start()
