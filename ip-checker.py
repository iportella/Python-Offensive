#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# =============================================================================
#  ██╗██████╗      ██████╗██╗  ██╗███████╗ ██████╗ ███████╗███████╗██████╗ 
#  ██║██╔══██╗    ██╔════╝██║  ██║██╔════╝██╔═══██╗██╔════╝██╔════╝██╔══██╗
#  ██║██████╔╝    ██║     ███████║█████╗  ██║   ██║█████╗  █████╗  ██████╔╝
#  ██║██╔═══╝     ██║     ██╔══██║██╔══╝  ██║   ██║██╔══╝  ██╔══╝  ██╔══██╗
#  ██║██║         ╚██████╗██║  ██║███████╗╚██████╔╝██║     ███████╗██║  ██║
#  ╚═╝╚═╝          ╚═════╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝
# -----------------------------------------------------------------------------
#  IP Reputation Lookup Tool
# -----------------------------------------------------------------------------
#  Description : Performs lookup on the provided IP address in threat intel
#                databases that report malicious IP activity.
#  Sources     : VirusTotal, Shodan, AbuseIPDB, AlienVault OTX, IBM X-Force
#  Author      : Igor Portella
#  Email       : igorlllopesport@protonmail.com
#  Version     : 1.0
#  License     : MIT
#  Disclaimer  : For educational and authorized use only.
# =============================================================================

import os
import json
import requests

def save_json(data, filename):
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def check_ip_virustotal(ip):
    api_key = os.environ.get("VT_API_KEY")
    if not api_key:
        print("[!] VirusTotal API key not set.")
        return None
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error with VirusTotal API: {response.text}")
        return None
    return response.json()

def check_ip_abuseipdb(ip):
    api_key = os.environ.get("ABUSEIPDB_API_KEY")
    if not api_key:
        print("[!] AbuseIPDB API key not set.")
        return None
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Key': api_key}
    params = {'ipAddress': ip}
    response = requests.get(url, headers=headers, params=params)
    if response.status_code != 200:
        print(f"Error with AbuseIPDB API: {response.text}")
        return None
    return response.json()

def check_ip_shodan(ip):
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        print("[!] Shodan API key not set.")
        return None
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    response = requests.get(url)
    if response.status_code != 200:
        print(f"Error with Shodan API: {response.text}")
        return None
    return response.json()

def check_ip_alienvault(ip):
    api_key = os.environ.get("ALIENVAULT_API_KEY")
    if not api_key:
        print("[!] AlienVault API key not set.")
        return None
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general"
    headers = {"X-OTX-API-KEY": api_key}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error with AlienVault API: {response.text}")
        return None
    return response.json()

def check_ip_xforce(ip):
    api_key = os.environ.get("XFORCE_API_KEY")
    if not api_key:
        print("[!] X-Force API key not set.")
        return None
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip}"
    headers = {"Authorization": f"Bearer {api_key}"}
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        print(f"Error with X-Force API: {response.text}")
        return None
    return response.json()

def extract_and_print_info_abuseIPDB(data):
    info = data.get('data', {})
    print('\n######## AbuseIPDB ########\n')
    for tag in ["ipAddress", "abuseConfidenceScore", "countryCode", "usageType", "isp", "domain", "hostnames", "isTor", "totalReports"]:
        print(f"{tag}: {info.get(tag, 'N/A')}")
    print('\n#############################\n')

def extract_and_print_info_virustotal(data):
    info = data.get('data', {}).get('attributes', {})
    print('\n######## VirusTotal ########\n')
    for tag in ["network", "country", "as_owner", "last_analysis_stats"]:
        print(f"{tag}: {info.get(tag, 'N/A')}")
    results = info.get('last_analysis_results', {})
    for engine, engine_data in results.items():
        if engine_data['category'] not in ['undetected', 'harmless']:
            print(f"Engine: {engine}")
            print(f"Category: {engine_data['category']}")
            print(f"Result: {engine_data['result']}")
            print(f"Method: {engine_data['method']}")
            print(f"Engine name: {engine_data['engine_name']}")
            print("-----------------")
    print('#############################')

def main():
    ip = input("Digite o IP: ")

    data_abuseipdb = check_ip_abuseipdb(ip)
    if data_abuseipdb:
        extract_and_print_info_abuseIPDB(data_abuseipdb)
        save_json(data_abuseipdb, 'abuseipdb.json')

    data_virustotal = check_ip_virustotal(ip)
    if data_virustotal:
        extract_and_print_info_virustotal(data_virustotal)
        save_json(data_virustotal, 'virustotal.json')

    data_shodan = check_ip_shodan(ip)
    if data_shodan:
        save_json(data_shodan, 'shodan.json')

    data_alienvault = check_ip_alienvault(ip)
    if data_alienvault:
        save_json(data_alienvault, 'alienvault.json')

    data_xforce = check_ip_xforce(ip)
    if data_xforce:
        save_json(data_xforce, 'xforce.json')

if __name__ == "__main__":
    main()
