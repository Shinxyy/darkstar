"""
Darkstar - Security Scanning Framework

This is the main entry point for the Darkstar security scanning framework.
It handles command line arguments, target parsing, and orchestration of
various scanning modules based on the selected scan mode.

Modes:
    1. Passive: Light reconnaissance without active scanning
    2. Normal: Standard scanning with passive and selected active modules
    3. Aggressive: Full scanning with all active and aggressive modules

Usage:
    python main.py -t TARGET -m MODE -d DOMAIN -env ENV_FILE

License:
    GNU General Public License v3.0
"""

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
import pandas as pd
import warnings
from scanners.bbot import BBotScanner
from scanners.nuclei import NucleiScanner, WordPressNucleiScanner
from scanners.vulnscan.openvas import openvas
from colorama import Fore, Style, init
from scanners.recon import WordPressDetector
import asyncio
import os
from scanners.portscan import RustScanner, run_rustscan, process_scan_results
from tools.bruteforce import process_bruteforce_results
from core.utils import categorize_targets, create_target_dataframe, log_target_summary
import logging
from concurrent.futures import ThreadPoolExecutor
from common.logger import setup_logger
from core.utils import get_scan_targets, prepare_output_directory


setup_logger()
logger = logging.getLogger("main")

warnings.filterwarnings("ignore")
init(autoreset=True)


def setup_env_from_args(args=None):
    # ? First, create a minimal argument parser just to grab the --envfile parameter.
    env_parser = argparse.ArgumentParser(add_help=False)
    env_parser.add_argument(
        "-env",
        "--envfile",
        help="envfile location, default .env",
        default=".env",
        required=False,
    )

    # Only parse sys.argv if args is not provided (for testing)
    if args is None:
        env_args, _ = env_parser.parse_known_args()
    else:
        env_args, _ = env_parser.parse_known_args(args)

    # ? Load the env file early.
    load_dotenv(env_args.envfile if hasattr(env_args, "envfile") else ".env")

    return env_args


class worker:
    """
    Main worker class that orchestrates and executes scanning operations.

    This class is responsible for running the selected scanning modules
    based on the specified mode and managing the workflow between them.

    Attributes:
        all_targets (str): Raw target string from command line arguments
        target_df (DataFrame): Parsed targets organized by type
        mode (int): Scan intrusiveness level (1=passive, 2=normal, 3=aggressive)
        org_domain (str): Organization name for database storage
    """

    def __init__(
        self,
        mode: int,
        targets: str,
        target_df: pd.DataFrame,
        org_name: str,
        bruteforce: bool = False,
        bruteforce_timeout: int = 300,
    ):
        self.all_targets = targets
        self.target_df = target_df
        self.mode = mode
        self.org_domain = org_name
        self.bruteforce = bruteforce
        self.bruteforce_timeout = bruteforce_timeout

    async def run(self):
        """
        Execute the scanning process based on the selected mode.

        Uses asynchronous execution to run independent tasks in parallel.
        """

        # ? Aggressive mode
        if self.mode == 3:
            all_scan_targets = get_scan_targets(self.target_df)

            # Define all the tasks we'll need to run
            async def run_port_discovery():
                logger.info(
                    f"{Fore.CYAN}Starting RustScan port discovery...{Style.RESET_ALL}"
                )

                # Create the output directory using our utility function
                rustscan_dir = prepare_output_directory(self.org_domain, "rustscanpy")

                # Initialize RustScanner with default settings and enable service detection
                rust_scanner = RustScanner(
                    batch_size=25000,
                    ulimit=35000,
                    timeout=3500,
                    concurrent_limit=2,
                    tries=1,
                    service_detection=True,  # Enable service detection in aggressive mode
                )

                # Run RustScan with individual files per target
                rustscan_results = await run_rustscan(
                    rust_scanner,
                    all_scan_targets,
                    output_dir=rustscan_dir,
                    all_in_one=False,  # Save separate file for each target
                    run_bruteforce=self.bruteforce,  # Enable bruteforce if specified
                    bruteforce_timeout=self.bruteforce_timeout,
                )

                # Process results
                scan_processed = process_scan_results(rustscan_results, self.org_domain)

                # Process bruteforce results if present
                bruteforce_processed = None
                if (
                    isinstance(rustscan_results, dict)
                    and "bruteforce_results" in rustscan_results
                ):
                    bruteforce_processed = process_bruteforce_results(
                        rustscan_results["bruteforce_results"]
                    )

                return {
                    "rustscan_results": rustscan_results,
                    "scan_processed": scan_processed,
                    "bruteforce_processed": bruteforce_processed,
                }

            async def run_bbot_scan():
                logger.info(
                    f"{Fore.CYAN}Starting bbot aggressive scan...{Style.RESET_ALL}"
                )

                # Run in a thread pool since bbot is likely not async-friendly
                with ThreadPoolExecutor() as executor:
                    bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: bbot_scanner.run(aggressive_mode=True)
                    )

                # Get the generated filename
                filename = (
                    f"{bbot_scanner.folder}/{bbot_scanner.foldername}/subdomains.txt"
                )
                if not os.path.exists(filename):
                    filename = "/tmp/subs.txt"  # Fallback

                return {"bbot_scanner": bbot_scanner, "subdomains_file": filename}

            async def run_nuclei_scan(filename):
                logger.info("Running nuclei scan on discovered subdomains")

                with ThreadPoolExecutor() as executor:
                    nuclei_scanner = NucleiScanner(filename, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, nuclei_scanner.run
                    )

            async def detect_wordpress(filename):
                with ThreadPoolExecutor() as executor:
                    wordpress_domains = await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: WordPressDetector().run(filename)
                    )

                logger.info(
                    f"{Fore.GREEN}[+] Wordpress Domains: {Fore.CYAN}{wordpress_domains}{Style.RESET_ALL}"
                )
                return wordpress_domains

            async def run_wordpress_nuclei(domains):
                if domains:
                    logger.info("Running WordPress-specific nuclei scan")

                    with ThreadPoolExecutor() as executor:
                        wp_scanner = WordPressNucleiScanner(domains, self.org_domain)
                        await asyncio.get_event_loop().run_in_executor(
                            executor, wp_scanner.run
                        )
                else:
                    logger.info(
                        "No WordPress sites found, skipping WordPress-specific scans"
                    )

            async def run_openvas_scan():
                if not self.target_df["IPv4"].empty:
                    logger.info("Starting OpenVAS scan on IPv4 targets")

                    with ThreadPoolExecutor() as executor:
                        openvas_handler = openvas(
                            targets=self.target_df["IPv4"], org_name=self.org_domain
                        )
                        await asyncio.get_event_loop().run_in_executor(
                            executor, openvas_handler.run
                        )
                else:
                    logger.warning(
                        f"{Fore.RED}[-] No IPv4 targets found, skipping OpenVAS{Style.RESET_ALL}"
                    )

            # Execute port discovery and bbot in parallel
            port_discovery_task = asyncio.create_task(run_port_discovery())
            bbot_task = asyncio.create_task(run_bbot_scan())

            # Wait for both to complete
            port_results, bbot_results = await asyncio.gather(
                port_discovery_task, bbot_task
            )

            # Now run nuclei, wordpress detection, and openvas in parallel
            tasks = [
                run_nuclei_scan(bbot_results["subdomains_file"]),
                run_openvas_scan(),
            ]

            # First detect WordPress
            wordpress_domains = await detect_wordpress(bbot_results["subdomains_file"])

            # Then add WordPress-specific nuclei task if needed
            tasks.append(run_wordpress_nuclei(wordpress_domains))

            # Wait for all remaining tasks to complete
            await asyncio.gather(*tasks)

        # ? Normal mode
        elif self.mode == 2:
            # Run these tasks in parallel
            tasks = []

            # Define bbot passive task
            async def run_bbot_passive():
                logger.info(
                    f"{Fore.CYAN}Starting bbot passive scan...{Style.RESET_ALL}"
                )

                with ThreadPoolExecutor() as executor:
                    bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                    await asyncio.get_event_loop().run_in_executor(
                        executor, lambda: bbot_scanner.run(aggressive_mode=False)
                    )

            tasks.append(run_bbot_passive())

            # Add OpenVAS if we have IPv4 targets
            if not self.target_df["IPv4"].empty:

                async def run_openvas():
                    logger.info("Starting OpenVAS scan on IPv4 targets")

                    with ThreadPoolExecutor() as executor:
                        openvas_handler = openvas(
                            targets=self.target_df["IPv4"], org_name=self.org_domain
                        )
                        await asyncio.get_event_loop().run_in_executor(
                            executor, openvas_handler.run
                        )

                tasks.append(run_openvas())
            else:
                logger.warning(
                    f"{Fore.RED}[-] No IPv4 targets found, skipping OpenVAS{Style.RESET_ALL}"
                )

            # Run all tasks in parallel
            await asyncio.gather(*tasks)

        # ? Passive mode
        elif self.mode == 1:
            with ThreadPoolExecutor() as executor:
                bbot_scanner = BBotScanner(self.all_targets, self.org_domain)
                await asyncio.get_event_loop().run_in_executor(
                    executor, lambda: bbot_scanner.run(aggressive_mode=False)
                )
        else:
            logger.error(
                f"{Fore.RED}[-] Invalid mode {self.mode} specified{Style.RESET_ALL}"
            )


def parse_targets(targets_str: str) -> pd.DataFrame:
    """
    Parse and categorize targets by type using proper validation.
    Returns:
        pd.DataFrame: DataFrame with targets categorized by type
    """
    targets = [target.strip() for target in targets_str.split(",") if target.strip()]
    if not targets:
        logger.warning(f"{Fore.YELLOW}[!] No valid targets provided{Style.RESET_ALL}")
        return pd.DataFrame()
    categorized = categorize_targets(targets)
    log_target_summary(categorized)

    return create_target_dataframe(categorized)


def main(args=None):
    """
    Main function that parses arguments and initializes the scanning process.

    Handles command line arguments, parses and categorizes targets by type,
    and initializes the worker to run the scanning process.

    Args:
        args: Command line arguments (for testing)
    """
    # Initialize environment variables
    setup_env_from_args(args)

    # ? Argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-t",
        "--target",
        required=True,
        help="Fill in the CIDR, IP or domain (without http/https) to scan",
    )
    parser.add_argument(
        "-m",
        "--mode",
        type=int,
        required=True,
        help="Scan intrusiveness: 1. passive, 2. normal, 3. aggressive",
        choices=[1, 2, 3],
    )
    parser.add_argument(
        "-d",
        "--domain",
        help="The organisation name necessary for database selection",
        required=True,
    )
    parser.add_argument(
        "--bruteforce",
        action="store_true",
        help="Enable bruteforce attacks on discovered services",
    )
    parser.add_argument(
        "--bruteforce-timeout",
        type=int,
        default=300,
        help="Timeout for each bruteforce attack in seconds",
    )
    parser.add_argument(
        "-env",
        "--envfile",
        help="envfile location, default .env",
        default=".env",
        required=False,
    )

    # ? Parse arguments
    if args is None:
        args = parser.parse_args()
    else:
        args = parser.parse_args(args)

    # Banner
    logger.info(f"{Fore.BLUE}{'=' * 60}")
    logger.info(f"{Fore.CYAN}DARKSTAR SECURITY SCANNING FRAMEWORK")
    logger.info(
        f"{Fore.CYAN}Mode: {Fore.YELLOW}{args.mode}{Fore.CYAN} | Target(s): {Fore.YELLOW}{args.target}{Fore.CYAN} | Organization: {Fore.YELLOW}{args.domain}"
    )
    logger.info(f"{Fore.BLUE}{'=' * 60}{Style.RESET_ALL}")

    # Parse targets
    target_df = parse_targets(args.target)

    # Display scan mode information
    mode_info = {
        1: f"{Fore.GREEN}PASSIVE MODE{Style.RESET_ALL} - Light reconnaissance without active scanning",
        2: f"{Fore.YELLOW}NORMAL MODE{Style.RESET_ALL} - Standard scanning with passive and selected active modules",
        3: f"{Fore.RED}AGGRESSIVE MODE{Style.RESET_ALL} - Full scanning with all active and aggressive modules",
    }
    logger.info(f"Initializing scan in {mode_info[args.mode]}")

    # ? Run the scanner
    scanner = worker(
        mode=args.mode,
        targets=args.target,
        target_df=target_df,
        org_name=args.domain,
        bruteforce=args.bruteforce,
        bruteforce_timeout=args.bruteforce_timeout,
    )

    asyncio.run(scanner.run())


if __name__ == "__main__":
    main()
