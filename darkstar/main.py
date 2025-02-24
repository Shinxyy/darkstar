#  *
#  * This file is part of Darkstar.
#  *
#  * Darkstar is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * Darkstar is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with Darkstar. If not, see <https://www.gnu.org/licenses/>.
#  *

import argparse
from dotenv import load_dotenv

#? First, create a minimal argument parser just to grab the --envfile parameter.
env_parser = argparse.ArgumentParser(add_help=False)
env_parser.add_argument("-env", "--envfile", help="envfile location, default .env", default=".env", required=True)
env_args, remaining_args = env_parser.parse_known_args()

#? Load the env file early.
load_dotenv(env_args.envfile)

import pandas as pd
import warnings
from modules.scanners import *
from modules.openvas import openvas
from colorama import Fore, Style, init
from modules.recon import WordPressDetector
warnings.filterwarnings("ignore")
init(autoreset=True)

class worker():
    def __init__(self, mode: int, targets: str, target_df: pd.DataFrame, org_name: str):
        self.all_targets = targets
        self.target_df = target_df
        self.mode = mode
        self.org_domain = org_name

    def run(self):
        #? Aggressive mode
        if self.mode == 3:
            # #? Run bbot with aggressive settings
            # bbot_scanner = bbot(self.all_targets, self.org_domain)
            # bbot_scanner.aggressive()
            
            # #? Run nuclei on the subdomains
            # filename = f'{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt'
            # nuclei(filename, self.org_domain).run()

            #? Detect wordpress
            filename = '/tmp/subs.txt'
            wordpress_domains = WordPressDetector().run(filename) 
            print(f"[+] Wordpress Domains: {wordpress_domains}")
            #? Nuclei wordpress
            nuclei_wordpress(wordpress_domains, self.org_domain).run()

            #? Run OpenVas
            openvas_handler = openvas(targets=self.all_targets, org_name=self.org_domain)
            openvas_handler.run()
        
        #? Normal mode
        elif self.mode == 2:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
            #? Run OpenVas
            if self.target_df['IPv4'].size > 0:
                openvas_handler = openvas(targets=self.target_df['IPv4'], org_name=self.org_domain)
                openvas_handler.run()
            else:
                print(f"{Fore.RED}[-] No IPv4 targets found, skipping OpenVAS{Style.RESET_ALL}")

        #? Passive mode
        elif self.mode == 1:
            bbot_scanner = bbot(self.all_targets, self.org_domain)
            bbot_scanner.passive()
        else:
            print(f"{Fore.RED}[-] Invalid mode {Style.RESET_ALL}")


def main():
    #? Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", required=True, help="Fill in the CIDR, IP or domain (without http/https) to scan")
    parser.add_argument("-m", "--mode", type=int, required=True, help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive", choices=[1, 2, 3])
    parser.add_argument("-d", "--domain", help="The organisation name necessary for database selection", required=True)
    parser.add_argument("-env", "--envfile", help="envfile location, default .env", default=".env", required=True)
    #? Parse arguments
    args = parser.parse_args()
    
    targets = args.target.split(',')
    cidrs, ipv4, ipv6, domains, urls = [], [], [], [], []

    for target in targets:
        if "http" in target:
            print(f"{Fore.GREEN}[+] Target {target} is a URL{Style.RESET_ALL}")
            urls.append(target)
        elif "/" in target:
            print(f"{Fore.GREEN}[+] Target {target} is CIDR{Style.RESET_ALL}")
            cidrs.append(target)
        elif ":" in target:
            print(f"{Fore.GREEN}[+] Target {target} is an IPv6{Style.RESET_ALL}")
            ipv6.append(target)
        elif target.replace(".", "").isnumeric():
            print(f"{Fore.GREEN}[+] Target {target} is an IP{Style.RESET_ALL}")
            ipv4.append(target)
        else:
            print(f"{Fore.GREEN}[+] Target {target} is a domain{Style.RESET_ALL}")
            domains.append(target)
    
    print(f"{Fore.MAGENTA}[>] CIDRs: {cidrs}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] IPs: {ipv4}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] Domains: {domains}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] IPv6: {ipv6}{Style.RESET_ALL}")
    print(f"{Fore.MAGENTA}[>] URLs: {urls}{Style.RESET_ALL}")
    
    print(f"{Fore.GREEN}[+] Targets Locked!{Style.RESET_ALL}")

    # Create a DataFrame from the lists
    target_data = {
        'CIDRs': cidrs,
        'IPv4': ipv4,
        'IPv6': ipv6,
        'Domains': domains,
        'URLs': urls
    }
    target_df = pd.DataFrame(dict([(k, pd.Series(v)) for k, v in target_data.items()]))

    #? Run the scanner
    scanner = worker(mode=args.mode, targets=args.target, target_df=target_df, org_name=args.domain)
    scanner.run()


if __name__ == "__main__":
    main()