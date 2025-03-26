import logging
import os
import time
from pycti import OpenCTIApiClient
from typing import List, Optional

# Configure logging
logging.basicConfig(level=logging.INFO)

# OpenCTI API configuration
API_URL = "http://localhost:8080/"
API_TOKEN = "05fe83ad-55a9-4771-8016-c8e12a97713a"
opencti_api_client = OpenCTIApiClient(API_URL, API_TOKEN)

RULE_ID_FILE = "last_rule_id.txt"
OUTPUT_FILE_PATH = r"D:\thesis\dvwa persis\modsec\modsecurity_rules.conf"

def get_next_rule_id() -> int:
    """Get the next unique rule ID."""
    try:
        if os.path.exists(RULE_ID_FILE):
            with open(RULE_ID_FILE, 'r') as f:
                last_id = int(f.read().strip())
        else:
            last_id = 1000000  # Start from 1000000

        next_id = last_id + 1
        with open(RULE_ID_FILE, 'w') as f:
            f.write(str(next_id))

        return next_id
    except Exception as e:
        logging.error(f"Error accessing rule ID file: {e}")
        raise

def fetch_all_observables(observable_type: str) -> List[dict]:
    """Fetch all observables of a given type using pagination."""
    all_observables = []
    search_after = None

    try:
        while True:
            observables_batch = opencti_api_client.stix_cyber_observable.list(
                types=[observable_type], first=100, search_after=search_after
            )

            if not observables_batch:
                break  # No more observables to fetch

            all_observables.extend(observables_batch)
            search_after = observables_batch[-1]['id']  # Move pagination forward

            logging.info(f"Fetched {len(observables_batch)} {observable_type} observables...")

        return all_observables

    except Exception as e:
        logging.error(f"Error fetching {observable_type} observables: {e}")
        return []

def fetch_observables() -> Optional[List[str]]:
    """
    Fetch observables of types IPv4 addresses, domain names, and URLs from OpenCTI.

    Returns:
        List[str]: A list of ModSecurity rules or None if an error occurs or no observables are found.
    """
    try:
        # Fetch all observables with pagination
        ip_observables = fetch_all_observables("IPv4-Addr")
        domain_observables = fetch_all_observables("Domain-Name")

        all_observables = ip_observables + domain_observables

        if not all_observables:
            logging.info("No observables found.")
            return None

        modsecurity_rules = []

        for observable in all_observables:
            observable_value = observable.get('value')  # Correct key
            observable_score = observable.get('x_opencti_score', 0)  # Default score to 0

            if observable_value and observable_score >= 60:
                rule_id = get_next_rule_id()
                logging.info(f"Processing {observable_value} (Score: {observable_score})")

                # Generate rules based on entity type
                entity_type = observable.get('entity_type')
                if entity_type == "IPv4-Addr":
                    rule = f'SecRule REMOTE_ADDR "{observable_value}" "id:{rule_id},phase:1,deny,status:403,msg:\'Blocked IP {observable_value}\'"'
                    modsecurity_rules.append(rule)
                elif entity_type == "Domain-Name":
                    escaped_value = observable_value.replace(".", "\\.")  # Escape dots
                    rule = f'SecRule REQUEST_HEADERS:Host "@rx ^([a-z0-9-]+\\.)*{escaped_value}$" "id:{rule_id},phase:1,deny,status:403,msg:\'Blocked Domain {observable_value} and subdomains\'"'
                    modsecurity_rules.append(rule)

        return modsecurity_rules

    except Exception as e:
        logging.error(f"Error fetching observables: {e}")
        return None

if __name__ == "__main__":
    try:
        start_time = time.time()
        modsecurity_rules = fetch_observables()
        elapsed_time = time.time() - start_time

        logging.info(f"Time taken to fetch observables: {elapsed_time:.2f} seconds")

        if modsecurity_rules:
            logging.info("ModSecurity rules generated successfully.")

            try:
                with open(OUTPUT_FILE_PATH, "w") as f:
                    f.write("\n".join(modsecurity_rules) + "\n")
                logging.info("Rules written to modsecurity_rules.conf")
            except PermissionError as e:
                logging.error(f"Permission error writing to modsecurity_rules.conf: {e}")
            except Exception as e:
                logging.error(f"Unexpected error writing to modsecurity_rules.conf: {e}")
        else:
            logging.info("No observables could be fetched.")
    except Exception as e:
        logging.error(f"Critical error: {e}")
