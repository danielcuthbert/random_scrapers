#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HTTP2 Scanner - Check domains for HTTP/2 support via ALPN.
# Author: Daniel Cuthbert
# Version: 0.3.3

import subprocess
import argparse
from concurrent.futures import ThreadPoolExecutor
import csv

MAX_THREADS = 20  # adjust this to your liking and performance of your machine


def banner():
    print(
        """
          ╦ ╦╔╦╗╔╦╗╔═╗  ╔═╗┌─┐┌─┐┌┐┌┌┐┌┌─┐┬─┐
          ╠═╣ ║  ║ ╠═╝  ╚═╗│  ├─┤││││││├┤ ├┬┘
          ╩ ╩ ╩  ╩ ╩    ╚═╝└─┘┴ ┴┘└┘┘└┘└─┘┴└─
          Version 0.3.3
          @danielcuthbert
          """
    )


def read_domains_from_file(file_path):
    with open(file_path, "r") as file:
        domains = file.readlines()
    return [domain.strip() for domain in domains]


def check_alpn_support(domain, port=443, debug=False, verbosity=0, timeout=10):
    command = [
        "openssl",
        "s_client",
        "-alpn",
        "h2, h3",
        "-connect",
        f"{domain}:{port}",
        "-status",
    ]

    if debug:
        command.append("-debug")

    if verbosity >= 1:
        print(f"Checking domain {domain}...")
    if verbosity >= 2:
        print(f"Using command: {' '.join(command)}")

    try:
        output = subprocess.check_output(
            command, input=b"bobby", stderr=subprocess.STDOUT, timeout=timeout
        )

        if b"ALPN protocol: h2" in output:
            return f"{domain} supports HTTP/2 via Application-Layer Protocol Negotiation (ALPN)!"
        elif b"ALPN protocol: " in output:
            return f"{domain} does NOT support HTTP/2 or HTTP/3 via ALPN."
        elif b"ALPN protocol: h3" in output:
            return f"{domain} supports HTTP/3 via ALPN!"
        else:
            return f"{domain} does NOT support HTTP/2 or HTTP/3 via ALPN or there was an error."

    except subprocess.TimeoutExpired:
        return f"Timeout expired while checking {domain}. The command took longer than {timeout} seconds."
    except subprocess.CalledProcessError as e:
        return f"Error executing command for {domain}. Command exited with status {e.returncode}: {e.output.decode('utf-8')}"
    except FileNotFoundError:
        return "Error: 'openssl' command not found. Please ensure OpenSSL is installed and available in your PATH."
    except Exception as e:
        return f"An unexpected error occurred while checking {domain}: {str(e)}"


def get_args():
    parser = argparse.ArgumentParser(
        description="Check domains for HTTP/2 & HTTP/3 support via Application-Layer Protocol Negotiation (ALPN)"
    )
    parser.add_argument("--file", required=True, help="Path to the file with domains.")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for openssl."
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity level. Can be used multiple times, e.g., -vvv.",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Maximum time (in seconds) allowed for the openssl command to run. Default is 10 seconds.",
    )
    parser.add_argument(
        "--output",
        default="results.csv",
        help="Path to the output file. Default is 'results.csv in the same directory this script is run from'.",
    )
    return parser.parse_args()


if __name__ == "__main__":
    banner()
    args = get_args()
    print("Checking domains for HTTP/2 & HTTP/3 support via ALPN...")

    domains = read_domains_from_file(args.file)

    def check_domain(domain):
        print(f"Checking {domain}...")
        return domain, check_alpn_support(
            domain, debug=args.debug, verbosity=args.verbose, timeout=args.timeout
        )

    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        results = list(executor.map(check_domain, domains))

    with open(args.output, "w", newline="") as csvfile:
        csv_writer = csv.writer(csvfile)
        csv_writer.writerow(["Domain", "Result"])  # Writing headers
        for domain, result in results:
            csv_writer.writerow([domain, result])
    print(f"Results saved to {args.output}")

    # Print results to the console
    for domain, result in results:
        print(result)
