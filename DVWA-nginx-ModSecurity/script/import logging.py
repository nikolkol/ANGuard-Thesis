import logging
import os
import time
from pycti import OpenCTIApiClient
from typing import List, Optional

logging.basicConfig(level=logging.INFO)

API_URL = "http://localhost:8080/"
API_TOKEN = "05fe83ad-55a9-4771-8016-c8e12a97713a"
opencti_api_client = OpenCTIApiClient(API_URL, API_TOKEN)

RULE_ID_FILE = "last_rule_id.txt"

def get_next_rule_id() -> int:
    """Get the next unique rule ID."""
    if os.path.exists(RULE_ID_FILE):
        with open(RULE_ID_FILE, 'r') as f:
            last_id = int(f.read().strip())
    else:
        last_id = 1000000 

    next_id = last_id + 1

    with open(RULE_ID_FILE, 'w') as f:
        f.write(str(next_id))

    return next_id

def fetch_observables() -> Optional[List[str]]:
    """
    Fetch observables of types IPv4 addresses, domain names, and URLs from OpenCTI.

    Returns:
        List[str]: A list of ModSecurity rules or None if an error occurs or no observables are found.
    """
    try:
        ip_observables = opencti_api_client.stix_cyber_observable.list(
            types=["IPv4-Addr"],
        )
        domain_observables = opencti_api_client.stix_cyber_observable.list(
            types=["Domain-Name"],
        )

        all_observables = ip_observables + domain_observables

        if not all_observables:
            logging.info("No observables found.")
            return None

        modsecurity_rules = []

        for observable in all_observables:
            observable_value = observable.get('observable_value')
            observable_score = observable.get('x_opencti_score', 0)

            if observable_value and observable_score >= 60:
                rule_id = get_next_rule_id()  
                logging.info(f"Observable Value: {observable_value} (Score: {observable_score})")

                if observable['entity_type'] == "IPv4-Addr":
                    rule = f'SecRule REMOTE_ADDR "@ipMatch {observable_value}" "id:{rule_id},phase:1,deny,status:403,msg:\'Blocked IP {observable_value}\'"'
                    modsecurity_rules.append(rule)
                elif observable['entity_type'] == "Domain-Name":
                    rule = f'SecRule REQUEST_HEADERS:Host "@streq {observable_value}" "id:{rule_id},phase:1,deny,status:403,msg:\'Blocked Domain {observable_value}\'"'
                    modsecurity_rules.append(rule)
        return modsecurity_rules

    except Exception as e:
        logging.error(f"Error fetching observables: {e}")
        return None

if __name__ == "__main__":
    start_time = time.time()
    modsecurity_rules = fetch_observables()
    end_time = time.time()
    elapsed_time = end_time - start_time

    logging.info(f"Time taken to fetch observables: {elapsed_time:.2f} seconds")

    if modsecurity_rules:
        logging.info("ModSecurity rules generated successfully.")

        with open("modsecurity_rules.conf", "w") as f:
            for rule in modsecurity_rules:
                f.write(rule + "\n")
        logging.info("Rules written to modsecurity_rules.conf")
        current_directory = os.getcwd()
        print(f"Current working directory: {current_directory}")

    else:
        logging.info("No observables could be fetched.")