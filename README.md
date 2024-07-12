# Gigamon Inline Map Rule Manager

## Overview
  This Python script is designed to manage rules in inline maps of Gigamon devices. It automates the addition and removal of rules based on IP addresses provided in a CSV file, facilitating the maintenance of blacklists of IP addresses.

## Features
  - Obtain inline maps from a Gigamon cluster
  - Add IP block rules
  - Remove IP block rules
  - Read IP addresses from CSV or Excel files
  - Continuously update rules every 60 seconds

## Table of Contents
  - Requirements
  - Installation
  - Usage
  - Code Structure
  - Contribution
  - License

## Requirements
  - Python 3.x
  - Access to the GigaVUE-FM API with valid credentials
  - CSV or Excel files containing the IP addresses to be blocked
  - A file containing the IDs of the GigaVUE-FM clusters
  
## Installation
  1. Clone the repository:

  `git clone https://github.com/n1y4m1/gigamon_inline_mitigation`

  `cd gigamon_inline_mitigation`

  2. Install the dependencies:

  `pip install -r requirements.txt`

  3. Configure the environment variables or edit the following parameters directly in the code:
  - **FM_IP**
  - **USERNAME**
  - **PASSWORD**

  4. Create the necessary files:
  - `<Blacklist_File>.csv`: File containing the IP addresses to be blocked.
  - `<FM_Nodes_File>.txt`: File containing the IDs of the GigaVUE-FM clusters, one per line.

## Usage
  Run the script:

  `python3 mitigation.py`
  
The script will start and update the IP block rules every 60 seconds.

## Code Structure
  - `get_inline_maps(cluster_id)`: Obtains all inline maps from a cluster.
  - `add_rule_to_map(cluster_id, map_alias, ip, rule_id, used_rule_ids)`: Adds an IP block rule to a map.
  - `remove_rule_from_map(cluster_id, map_alias, rule_id)`: Removes a rule from a map.
  - `load_ips_from_file(file_path)`: Loads IP addresses from a CSV or Excel file.
  - `get_drop_rules(cluster_id, map_alias)`: Obtains the block rules from a map.
  - `find_lowest_available_rule_id(used_rule_ids, max_rule_id=2000)`: Finds the lowest available rule ID.
  - `load_cluster_ids(file_path)`: Loads the cluster IDs from a file.
  - `update_rules(cluster_id)`: Updates the rules for a specific cluster.
  - `update_all_clusters()`: Starts threads to update all clusters.

## Contribution
  Contributions are welcome! Feel free to open issues and pull requests.

## License
This project is licensed under the MIT License.
