import threading
import xml.etree.ElementTree as ET
from datetime import datetime
import requests
import time
import netaddr
import logging  # Add missing logging import
from core.models.vulnerability import Vulnerability
from common.db_helper import insert_vulnerability_to_database
from common.config import OPENVAS_USER, OPENVAS_PASSWORD
import pandas as pd
from colorama import Fore, Style, init

# Initialize colorama for colored terminal output
init(autoreset=True)


class openvas:
    """
    Manages OpenVAS vulnerability scanning operations.

    This class handles target creation, task creation, scan execution,
    result retrieval, and vulnerability processing with the OpenVAS scanner.
    It can handle multiple types of targets including IPs and CIDR notation.

    Attributes:
        vulnerabilities (list): List to store found vulnerabilities
        queue_reportIDs (list): Queue of report IDs for ongoing scans
        queue_scan_names (list): Queue of scan names for ongoing scans
        queue_report_location (list): Queue of report file locations
        ips (str/list): IP addresses or networks to scan
        username (str): OpenVAS username from configuration
        password (str): OpenVAS password from configuration
        org_name (str): Organization name for database storage
        formatID (str): OpenVAS report format ID
        scanConfigID (str): OpenVAS scan configuration ID
    """

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
        self.command_prefix = ""
        self.alive_test = "ICMP, TCP-ACK Service &amp; ARP Ping"
        self.scanConfigID = (
            "daba56c8-73ec-11df-a475-002264764cea"  # Full and very deep ultimate
        )
        self.formatID = "a994b278-1f62-11e1-96ac-406186ea4fc5"
        self.org_name = org_name

    def get_report(self, reportID, report_location):
        """
        Retrieve a scan report from OpenVAS and save it to a file.

        Args:
            reportID (str): The ID of the report to retrieve
            report_location (str): File path where the report will be saved
        """
        try:
            print(
                f"{Fore.BLUE}[*] Retrieving report {reportID} to {report_location}{Style.RESET_ALL}"
            )
            command = f"{self.command_prefix} \"<get_reports report_id='{reportID}' filter='apply_overrides=0 levels=hml min_qod=50 first=1 rows=1000 sort=name ignore_pagination=1' details='1' format_id='{self.formatID}'/>\""
            response = requests.post(
                "http://automatic-propagation-gvmd-1:5000/get_report",
                json={"command": command},
            )
            report_data = response.json()["message"].strip()

            with open(report_location, "w") as f:
                f.write(report_data)
            print(
                f"{Fore.GREEN}[+] Successfully saved report to {report_location}{Style.RESET_ALL}"
            )
        except Exception as e:
            print(f"{Fore.RED}[!] Error getting report: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error getting report: {e}")

    def create_target(self):
        """
        Create a target in OpenVAS for scanning.

        Sets up a target with appropriate name, host information, and scanning parameters.
        Stores the created target ID in self.targetID.
        """
        self.report_location = (
            f"/tmp/report_openvas_{datetime.now().strftime('%Y%m%d%H%M%S')}.xml"
        )
        self.scan_name = f"Darkstar-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        self.queue_scan_names.append(self.scan_name)
        self.queue_report_location.append(self.report_location)
        command = f'{self.command_prefix} "<CREATE_TARGET><name>{self.scan_name}</name><hosts>{self.ip}</hosts><alive_tests>{self.alive_test}</alive_tests><port_range>1-65535</port_range></CREATE_TARGET>"'
        response = requests.post(
            "http://automatic-propagation-gvmd-1:5000/create_target",
            json={"command": command},
        )
        self.targetID = response.json()["message"]

    def create_task(self):
        """
        Create a scan task in OpenVAS.

        Uses the previously created target ID to establish a new scanning task.
        Stores the created task ID in self.taskID.
        """
        command = f'{self.command_prefix} \'<CREATE_TASK><name>{self.scan_name}</name><Comment>Openvas Scan on {self.ip}</Comment><target id="{self.targetID}" /><config id="{self.scanConfigID}" /></CREATE_TASK>\''
        response = requests.post(
            "http://automatic-propagation-gvmd-1:5000/create_task",
            json={"command": command},
        )
        self.taskID = response.json()["message"]

    def run_task(self):
        """
        Start the execution of a previously created OpenVAS task.

        Initiates the scan and adds the resulting report ID to the queue.
        """
        command = f"{self.command_prefix} '<start_task task_id=\"{self.taskID}\"/>'"
        response = requests.post(
            "http://automatic-propagation-gvmd-1:5000/run_task",
            json={"command": command},
        )
        self.reportID = response.json()["message"]
        self.queue_reportIDs.append(self.reportID)

    def check_if_finished(self, reportID):
        """
        Check if an OpenVAS scan is complete.

        Parses the XML response from OpenVAS to determine scan status and progress.

        Args:
            reportID (str): The ID of the report to check

        Returns:
            bool: True if scan is complete, False otherwise
        """
        try:
            # Using the GMP API directly without relying on the xml2 command
            command = f"{self.command_prefix} \"<get_reports report_id='{reportID}' format_id='{self.formatID}'/>\""
            response = requests.post(
                "http://automatic-propagation-gvmd-1:5000/check_if_finished",
                json={"command": command},
            )

            # Parse the XML response to get progress and status
            report_data = response.json()["message"].strip()
            try:
                root = ET.fromstring(report_data)
                # Find the scan status in the XML
                status_element = root.find(".//report/scan_run_status")
                if status_element is not None:
                    status = status_element.text
                    if status == "Done":
                        print(
                            f"{Fore.GREEN}[✓] Scan {reportID[:8]}... Done{Style.RESET_ALL}"
                        )
                        return True
                    elif status == "Running":
                        # Find the progress value - update to find correct path
                        progress_element = root.find(".//report/task/progress")
                        progress = "0"
                        if progress_element is not None:
                            progress = progress_element.text
                        progress_color = Fore.YELLOW
                        if int(progress) > 75:
                            progress_color = Fore.GREEN
                        elif int(progress) < 25:
                            progress_color = Fore.RED
                        print(
                            f"{Fore.CYAN}[OpenVAS 🌿] {progress_color}Running: {progress}% complete{Style.RESET_ALL}"
                        )
                        return False
                    else:
                        print(
                            f"{Fore.YELLOW}[OpenVAS 🌿] Status: {status}{Style.RESET_ALL}"
                        )
                        return False
                else:
                    print(
                        f"{Fore.RED}[!] Could not find scan status in response{Style.RESET_ALL}"
                    )
                    return False
            except ET.ParseError as e:
                print(
                    f"{Fore.RED}[!] Error parsing XML response: {str(e)}{Style.RESET_ALL}"
                )
                logging.error(f"Error parsing XML response: {e}")
                logging.error(f"Response data: {report_data}")
                return False
        except Exception as e:
            print(
                f"{Fore.RED}[!] Error checking scan status: {str(e)}{Style.RESET_ALL}"
            )
            logging.error(f"Error checking scan status: {e}")
            return False

    def wait_for_scan(self):
        """
        Monitor ongoing scans and process results when complete.

        Continuously checks scan status and processes completed scan reports.
        Removes completed scans from the queue.
        """
        print(f"{Fore.BLUE}[*] Starting scan monitor thread{Style.RESET_ALL}")
        while self.queue_scan_names:
            print(
                f"{Fore.CYAN}[*] Current Queue: {len(self.queue_scan_names)} scans remaining{Style.RESET_ALL}"
            )
            new_queue_scan_names = []
            new_queue_reportIDs = []
            new_queue_report_locations = []

            for scan, report_id, report_location in zip(
                self.queue_scan_names, self.queue_reportIDs, self.queue_report_location
            ):
                print(f"{Fore.BLUE}[*] Checking scan: {scan}{Style.RESET_ALL}")
                done = self.check_if_finished(reportID=report_id)
                if done:
                    print(
                        f"{Fore.GREEN}[+] Scan {scan} completed, retrieving report...{Style.RESET_ALL}"
                    )
                    self.get_report(reportID=report_id, report_location=report_location)
                    self.process_findings(report_location=report_location)
                else:
                    print(
                        f"{Fore.YELLOW}[*] Scan {scan} still in progress...{Style.RESET_ALL}"
                    )
                    # Keep scans that are not done
                    new_queue_scan_names.append(scan)
                    new_queue_reportIDs.append(report_id)
                    new_queue_report_locations.append(report_location)

            # Replace the old queues with the updated ones
            self.queue_scan_names = new_queue_scan_names
            self.queue_reportIDs = new_queue_reportIDs
            self.queue_report_location = new_queue_report_locations

            if self.queue_scan_names:
                print(
                    f"{Fore.BLUE}[*] Waiting 60 seconds before next check... ({len(self.queue_scan_names)} scans remaining){Style.RESET_ALL}"
                )
                time.sleep(60)
            else:
                print(f"{Fore.GREEN}[✓] All scans completed!{Style.RESET_ALL}")

    def process_findings(self, report_location) -> None:
        """
        Process vulnerability findings from an OpenVAS report.

        Parses an XML report file, extracts vulnerability information,
        and converts it to Vulnerability objects for database storage.

        Args:
            report_location (str): Path to the XML report file
        """
        print(
            f"{Fore.BLUE}[*] Processing findings from report: {report_location}{Style.RESET_ALL}"
        )
        try:
            tree = ET.parse(report_location)
            root = tree.getroot()
        except ET.ParseError as e:
            print(f"{Fore.RED}[!] Error parsing report XML: {str(e)}{Style.RESET_ALL}")
            logging.error(f"Error parsing report XML: {e}")
            return

        vulnerability_count = 0
        skipped_count = 0
        # Process each <result> element
        for result in root.findall(".//result"):
            try:
                name = result.find("name").text
            except Exception:
                continue

            # Skip known false positives
            if any(
                skip in name
                for skip in [
                    "httpOnly",
                    "Certificate Expired",
                    "Weak Encryption",
                    "Missing `secure`",
                    "VNC Server Unencrypted",
                    "Weak Cipher",
                    "Vulnerable Cipher",
                ]
            ):
                skipped_count += 1
                continue

            nvt = result.find("nvt")
            try:
                cve = nvt.find("cve").text  # May be "NOCVE"
            except Exception:
                cve = "NOCVE"

            # Default values
            exploit = False
            epss = 0.0

            port = result.find("port").text
            threat = result.find("threat").text
            severity = result.find(
                "severity"
            ).text  # This is used later as cvss info if needed
            poc2 = result.find("description").text
            endsolution = ""

            # If a valid CVE is provided, check EPSs from FIRST
            if cve != "NOCVE":
                response_epss = requests.get(
                    f"https://api.first.org/data/v1/epss?cve={cve}"
                )
                if response_epss.status_code == 200:
                    data = response_epss.json().get("data", [])
                    if data:
                        epss = float(data[0].get("percentile", 0))
                        if epss >= 0.65:
                            exploit = True

            host_ip = result.find("host").text
            qod = result.find("qod")
            qod_value = qod.find("value").text  # Confidence (as a string)

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
                    cve_number=cve,
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
                    epss=epss,
                )

            # For demonstration, print the vulnerability object (the __str__ method from CVE is available on vuln.cve)
            print(f"Found vulnerability: {vuln.title} on {vuln.affected_item}")

            # Finally, add the vulnerability to our local list
            self.vulnerabilities.append(vuln)

        for vuln in self.vulnerabilities:
            insert_vulnerability_to_database(vuln=vuln, org_name=self.org_name)

        print(
            f"{Fore.GREEN}[+] Processed {vulnerability_count} vulnerabilities ({skipped_count} skipped as false positives){Style.RESET_ALL}"
        )

    def split_cidr(self, cidr):
        """
        Split a large CIDR range into smaller subnets.

        For large networks, splits into /20 subnets for more manageable scanning.

        Args:
            cidr (str): CIDR notation of the network

        Returns:
            list: List of subnet strings
        """
        net = netaddr.IPNetwork(cidr)
        if net.prefixlen < 20:
            return [str(subnet) for subnet in net.subnet(20)]
        else:
            return [str(net)]

    def run(self):
        """
        Execute the complete OpenVAS scanning workflow.

        Validates targets, prepares command prefix, filters valid targets,
        creates and runs scan tasks, and initiates the monitoring thread.
        """
        # Check if there are any valid targets before proceeding
        # Handle pandas Series objects properly
        if self.ips is None:
            print(
                f"{Fore.YELLOW}[!] No targets provided for OpenVAS scan. Skipping...{Style.RESET_ALL}"
            )
            return

        # Check if it's a pandas Series
        if hasattr(self.ips, "empty") and self.ips.empty:
            print(
                f"{Fore.YELLOW}[!] Empty target list for OpenVAS scan. Skipping...{Style.RESET_ALL}"
            )
            return

        # Check if it's a pandas Series with only NaN values
        if (
            hasattr(self.ips, "isna")
            and hasattr(self.ips, "all")
            and self.ips.isna().all()
        ):
            print(
                f"{Fore.YELLOW}[!] No valid IPv4 targets for OpenVAS scan (only NaN values). Skipping...{Style.RESET_ALL}"
            )
            return

        self.command_prefix = (
            f"gosu gvmd gvm-cli --gmp-username {self.username} "
            f"--gmp-password '{self.password}'  socket "
            f"--socketpath /run/gvmd/gvmd.sock --xml"
        )

        target_list = []

        # Handle pandas Series
        if hasattr(self.ips, "apply"):
            # Convert pandas Series to list, filtering out NaN values
            valid_ips = self.ips.dropna().tolist()
            for ip in valid_ips:
                if ip and "/" not in str(ip):
                    target_list.append(str(ip))
                elif ip:
                    target_list.extend(self.split_cidr(str(ip)))
        # Handle string
        elif isinstance(self.ips, str):
            ip_list = self.ips.split(" ")
            for ip in ip_list:
                if ip and not pd.isna(ip) and "/" not in str(ip):
                    target_list.append(ip)
                elif ip and not pd.isna(ip):
                    target_list.extend(self.split_cidr(ip))
        # Handle list or tuple
        else:
            for ip in self.ips:
                if ip and not pd.isna(ip) and "/" not in str(ip):
                    target_list.append(str(ip))
                elif ip and not pd.isna(ip):
                    target_list.extend(self.split_cidr(str(ip)))

        # Double check that we have targets after filtering
        if not target_list:
            print(
                f"{Fore.YELLOW}[!] No valid IPv4 targets for OpenVAS scan after filtering. Skipping...{Style.RESET_ALL}"
            )
            return

        print(
            f"{Fore.GREEN}[+] Starting OpenVAS scan on {len(target_list)} targets{Style.RESET_ALL}"
        )
        for target in target_list:
            self.ip = target
            self.create_target()
            self.create_task()
            self.run_task()
            time.sleep(3)

        threading.Thread(target=self.wait_for_scan).start()
