#!/usr/bin/env python3

import requests
import pandas as pd
import time
from requests.auth import HTTPBasicAuth
from urllib3.exceptions import InsecureRequestWarning
import os
import threading
import json

# Supress only the single InsecureRequestWarning from urllib3 needed
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Configurações da API
FM_IP = 'https://<GigaVUE-FM IP Address>/api/v1.3'
USERNAME = '<user>'
PASSWORD = '<password>'
HEADERS = {
    'Accept': '*/*',
    'Content-Type': 'application/json'
}

# Function to get all classic inline maps in Gigamon Node
def get_inline_maps(cluster_id):
    url = f"{FM_IP}/maps?clusterId={cluster_id}&mapTypes=inline"
    response = requests.get(url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    if response.status_code == 200:
        return response.json()
    else:
        return None

# Function to create a rule using IPv4 source
def add_rule_to_map(cluster_id, map_alias, ip, rule_id, used_rule_ids):
    url = f"{FM_IP}/maps/{map_alias}/rules/drop?clusterId={cluster_id}"
    rule = {
        "ruleId": rule_id,
        "bidi": True,
        "matches": [
            {
                "type": "ip4Src",
                "value": ip,
                "netMask": "255.255.255.255"
            }
        ]
    }
    response = requests.post(url, headers=HEADERS, json=rule, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    if response.status_code == 201:
        print(f"Success: Added drop rule for IP: {ip} with ruleId: {rule_id} on cluster {cluster_id}, map {map_alias}")
        used_rule_ids.add(rule_id)
        return True
    elif response.status_code == 500 and "This maprule is a duplicate" in response.text:
        print(f"Duplicate rule detected for IP: {ip}, skipping addition...")
        return True
    elif response.status_code == 500 and "duplicate rule ID" in response.text:
        print(f"Duplicate rule ID detected for ruleId: {rule_id}, selecting a new ruleId...")
        return False
    elif response.status_code == 500 and "Failed to connect to the unified gateway" in response.text:
        print(f"Failed to connect to the unified gateway for IP: {ip}, retrying...")
        time.sleep(5)  # Espera 5 segundos antes de tentar novamente
        return False
    elif response.status_code == 500 and "Invalid request" in response.text:
        print(f"Invalid request for IP: {ip}. Request data: {json.dumps(rule)}")
        return False
    else:
        print(f"Error: Unable to add rule for IP: {ip} on cluster {cluster_id}, map {map_alias}. Status code: {response.status_code}")
        print(response.text)  # Print the response text for debugging
        return True

# Function to remove a rule 
def remove_rule_from_map(cluster_id, map_alias, rule_id):
    url = f"{FM_IP}/maps/{map_alias}/rules/{rule_id}?clusterId={cluster_id}"
    retry_count = 0
    while retry_count < 3:
        response = requests.delete(url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
        if response.status_code == 200 or response.status_code == 204:
            print(f"Success: Removed drop rule with ruleId: {rule_id} on cluster {cluster_id}, map {map_alias}")
            return True
        elif response.status_code == 500 and "Failed to connect to the unified gateway" in response.text:
            print(f"Failed to connect to the unified gateway for ruleId: {rule_id}, retrying...")
            retry_count += 1
            time.sleep(5)  # Espera 5 segundos antes de tentar novamente
        else:
            print(f"Error: Unable to remove rule with ruleId: {rule_id} on cluster {cluster_id}, map {map_alias}. Status code: {response.status_code}")
            print(response.text)  # Print the response text for debugging
            return False
    return False

# Function to load IP addresses from CSV file
def load_ips_from_file(file_path):
    file_ext = os.path.splitext(file_path)[-1].lower()
    if file_ext == '.csv':
        try:
            df = pd.read_csv(file_path, delimiter=',', on_bad_lines='skip')
        except pd.errors.ParserError as e:
            print(f"Error parsing CSV file: {e}")
            return []
    elif file_ext in ['.xls', '.xlsx']:
        try:
            df = pd.read_excel(file_path)
        except Exception as e:
            print(f"Error reading Excel file: {e}")
            return []
    else:
        raise ValueError("Unsupported file format: {}".format(file_ext))

    # Verify available columns from CSV
#    print("Available columns:", df.columns)

    # Verify if the 'Src Address' column is available
    df.columns = df.columns.str.strip()  # Removes blank spaces around column names
    if 'Src Address' not in df.columns:
        raise KeyError("The specified column 'Src Address' was not found.")

    return df['Src Address'].tolist()

# Function to get the map's drop rules
def get_drop_rules(cluster_id, map_alias):
    url = f"{FM_IP}/maps/{map_alias}?clusterId={cluster_id}"
    response = requests.get(url, headers=HEADERS, auth=HTTPBasicAuth(USERNAME, PASSWORD), verify=False)
    if response.status_code == 200:
        map_info = response.json()
        return map_info['map'].get('rules', {}).get('dropRules', [])
    else:
        print(f"Failed to retrieve drop rules for cluster {cluster_id}, map {map_alias}. Status code: {response.status_code}")
        print(response.text)  # Print the response text for debugging
        return []

# Function to find the smallest ruleId available from 3
def find_lowest_available_rule_id(used_rule_ids, max_rule_id=2000):
    for rule_id in range(3, max_rule_id + 1):
        if rule_id not in used_rule_ids:
            return rule_id
    return None

# Function to read Cluster IDs from the file
def load_cluster_ids(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file.readlines()]

# Main function for adding and removing rules
def update_rules(cluster_id):
    while True:
        maps_response = get_inline_maps(cluster_id)

        if maps_response and "maps" in maps_response:
            maps = maps_response["maps"]
            if maps:
                first_map = maps[0]
                map_alias = first_map['alias']
                drop_rules = get_drop_rules(cluster_id, map_alias)
                drop_ips = {rule['matches'][0]['value']: rule['ruleId'] for rule in drop_rules if rule['matches'][0]['type'] == 'ip4Src'}
                used_rule_ids = set(drop_ips.values())

                # Load IPs from CSV file
                ips = load_ips_from_file('<Blacklist_File>.csv')
                ips_set = set(ips)

                # Remove rules for IPs that are no longer in the file
                for ip, rule_id in drop_ips.items():
                    if ip not in ips_set:
                        remove_rule_from_map(cluster_id, map_alias, rule_id)
                        time.sleep(2)  # Wait 2 seconds between each request to avoid request rate problems

                # Add new rules for non-existent IPs
                for ip in ips_set - set(drop_ips.keys()):
                    # Updates the list of rules before adding a new one
                    drop_rules = get_drop_rules(cluster_id, map_alias)
                    used_rule_ids = {rule['ruleId'] for rule in drop_rules}
                    new_rule_id = find_lowest_available_rule_id(used_rule_ids)
                    if new_rule_id is not None:
                        while not add_rule_to_map(cluster_id, map_alias, ip, new_rule_id, used_rule_ids):
                            new_rule_id = find_lowest_available_rule_id(used_rule_ids)
                            if new_rule_id is None:
                                print(f"No available ruleId found for IP: {ip} on cluster {cluster_id}, map {map_alias}")
                                break
                        time.sleep(3)  # Wait 3 seconds between each request to avoid request rate problems
        else:
            print(f"Failed to retrieve maps or maps key is missing for cluster ID: {cluster_id}")

        print(f"Waiting for 60 seconds before the next update for cluster {cluster_id}...")
        time.sleep(60)

# Function to start the threads for each cluster ID
def update_all_clusters():
    cluster_ids = load_cluster_ids('<FM_Nodes_File>.txt')
    threads = []1

    for cluster_id in cluster_ids:
        thread = threading.Thread(target=update_rules, args=(cluster_id,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

# Continuous loop to update the rules every 60 seconds
while True:
    update_all_clusters()
    time.sleep(60)
