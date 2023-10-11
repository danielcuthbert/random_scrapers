#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# HTTP2 Scanner - Check domains for HTTP/2 support via ALPN.
# Author: Daniel Cuthbert
# Version: 0.2

import subprocess
import argparse


def read_domains_from_file(file_path):
    with open(file_path, "r") as file:
        domains = file.readlines()
    return [domain.strip() for domain in domains]


def check_alpn_support(domain, port=443, debug=False):
    command = [
        "openssl",
        "s_client",
        "-alpn",
        "h2",
        "-connect",
        f"{domain}:{port}",
        "-status",
    ]

    if debug:
        command.append("-debug")

    try:
        output = subprocess.check_output(
            command, input=b"bobby", stderr=subprocess.STDOUT
        )
        if b"ALPN protocol: h2" in output:
            return f"{domain} supports HTTP/2 via Application-Layer Protocol Negotiation (ALPN)!"
        elif b"ALPN protocol: " in output:
            return f"{domain} does NOT support HTTP/2 via Application-Layer Protocol Negotiation (ALPN)."
        else:
            return f"{domain} does NOT support HTTP/2 via Application-Layer Protocol Negotiation (ALPN) or there was an error."
    except subprocess.CalledProcessError as e:
        return f"Error executing command for {domain}. Command exited with status {e.returncode}: {e.output.decode('utf-8')}"
    except FileNotFoundError:
        return "Error: 'openssl' command not found. Please ensure OpenSSL is installed and available in your PATH."
    except Exception as e:
        return f"An unexpected error occurred while checking {domain}: {str(e)}"


def get_args():
    parser = argparse.ArgumentParser(
        description="Check domains for HTTP/2 support via ALPN."
    )
    parser.add_argument("--file", required=True, help="Path to the file with domains.")
    parser.add_argument(
        "--debug", action="store_true", help="Enable debug mode for openssl."
    )
    return parser.parse_args()


if __name__ == "__main__":
    args = get_args()
    print("Checking domains for HTTP/2 support via ALPN...")

    domains = read_domains_from_file(args.file)
    for domain in domains:
        print(f"Checking {domain}...")
        print(check_alpn_support(domain, debug=args.debug))
