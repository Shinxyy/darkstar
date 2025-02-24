import pandas as pd
import mysql.connector
from datetime import datetime
from modules.config import db_config
from modules.vulns import Vulnerability
import re
import json

def insert_bbot_to_db(dataframe: pd.DataFrame, org_name: str):
    try:
        connection = mysql.connector.connect(**db_config)
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute(f"USE {org_name}") #? Select the database for the organisation
            #? Iterate over DataFrame rows and insert into MySQL table
            for index, row in dataframe.iterrows():
                try:
                    event_type = json.dumps(json.loads(row["Event type"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    event_type = row["Event type"]

                try:
                    event_data = json.dumps(json.loads(row["Event data"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    event_data = row["Event data"]

                try:
                    ip_address = json.dumps(json.loads(row["IP Address"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    ip_address = row["IP Address"]

                try:
                    source_module = json.dumps(json.loads(row["Source Module"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    source_module = row["Source Module"]

                try:
                    scope_distance = json.dumps(json.loads(row["Scope Distance"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    scope_distance = row["Scope Distance"]

                try:
                    event_tags = json.dumps(json.loads(row["Event Tags"].replace("'", '"')))
                except (json.JSONDecodeError, AttributeError):
                    event_tags = row["Event Tags"]

                # Handle the edge case with single quotes in nested JSON
                if isinstance(event_data, str) and event_data.startswith("{") and event_data.endswith("}"):
                    event_data = event_data.replace("'", '"')

                current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                insert_query = """
                INSERT INTO asmevents (event_type, event_data, ip_address, source_module, scope_distance, event_tags, time)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """
                cursor.execute(insert_query, (event_type, event_data, ip_address, source_module, scope_distance, event_tags, current_time))

            #? Commit the transaction
            connection.commit()
            print("[+] Data inserted successfully into database.")
    except mysql.connector.Error as e:
        print(f"[-] Error: {e}")

    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("[+] Closed the MySQL connection.")

def sanitize_string(value):
    """Remove ANSI escape codes and trim strings."""
    
    if isinstance(value, str):
        return re.sub(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])', '', value).strip()
    return value

def flatten_list(value):
    """Convert a list to a comma-separated string."""
    print(f"Value: {value}")
    if isinstance(value, list):
        new = ', '.join(map(str, value))
        print(f"New: {new}, type: {type(new)}")
        return new
    return value

def convert_to_json(value):
    """Convert a dictionary to a JSON string."""
    if isinstance(value, dict):
        return json.dumps(value)
    return value

def prepare_cve_data(vuln):
    """Clean and prepare CVE data for database insertion."""
    title = sanitize_string(vuln.title).strip("[]")  # Sanitize title
    references = flatten_list(vuln.cve.references)  # Flatten references list
    pocs = flatten_list(vuln.cve.pocs)  # Flatten PoCs list
    impact = convert_to_json(vuln.cve.impact)  # Convert impact dict to JSON
    access = convert_to_json(vuln.cve.access)  # Convert access dict to JSON
    

    cve_data = (
        sanitize_string(vuln.cve.cve),  # Field 0
        title,                          # Field 1 (Sanitized)
        sanitize_string(vuln.affected_item),  # Field 2
        sanitize_string(vuln.tool),          # Field 3
        vuln.confidence,                     # Field 4
        sanitize_string(vuln.severity),      # Field 5
        sanitize_string(vuln.host),          # Field 6
        vuln.cve.cvss,                       # Field 7
        vuln.cve.epss,                       # Field 8 (Flattened)
        sanitize_string(vuln.cve.summary),   # Field 9
        sanitize_string(vuln.cve.cwe),       # Field 10
        references,                          # Field 11 (Flattened)
        sanitize_string(vuln.cve.capec),     # Field 12
        sanitize_string(vuln.cve.solution),  # Field 13
        impact,                              # Field 14 (JSON)
        access,                              # Field 15 (JSON)
        vuln.cve.age,                        # Field 16
        pocs,                                # Field 17 (Flattened)
        vuln.cve.kev                         # Field 18
    )
    
    # Debugging log: Ensure no lists remain
    print("CVE Data Types and Values:")
    for i, field in enumerate(cve_data):
        print(f"Field {i}: Type = {type(field)}, Value = {field}")
    
    return cve_data

def prepare_non_cve_data(vuln):
    """Clean and prepare non-CVE data for database insertion."""
    references = flatten_list(vuln.references)
    poc = flatten_list(vuln.poc)

    non_cve_data = (
        None,  # No CVE
        sanitize_string(vuln.title),
        sanitize_string(vuln.affected_item),
        sanitize_string(vuln.tool),
        vuln.confidence,
        sanitize_string(vuln.severity),
        sanitize_string(vuln.host),
        vuln.cvss,
        vuln.epss,
        sanitize_string(vuln.summary),
        sanitize_string(vuln.cwe),
        references,
        sanitize_string(vuln.capec),
        sanitize_string(vuln.solution),
        sanitize_string(vuln.impact),
        None,  # No access for non-CVE
        None,  # No age for non-CVE
        poc,
        None   # Non-CVE entries are not part of KEV
    )
    
    # Debugging log: Ensure no lists remain
    print("Non-CVE Data Types and Values:")
    for i, field in enumerate(non_cve_data):
        print(f"Field {i}: Type = {type(field)}, Value = {field}")

    return non_cve_data

def insert_vulnerability_to_database(vuln: Vulnerability, org_name: str):
    try:
        # Establish the database connection
        connection = mysql.connector.connect(**db_config)
        
        if connection.is_connected():
            cursor = connection.cursor()
            cursor.execute(f"USE {org_name}")
            # Define the INSERT query
            insert_query = """
            INSERT INTO vulnerability (
                cve, title, affected_item, tool, confidence, severity, host,
                cvss, epss, summary, cwe, `references`, capec, solution, impact,
                access, age, pocs, kev
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            
            # Check if the vulnerability has a CVE
            if hasattr(vuln, 'cve') and vuln.cve is not None:
                # Prepare CVE-based data
                cve_data = prepare_cve_data(vuln)
                cursor.execute(insert_query, cve_data)
            else:
                # Prepare non-CVE-based data
                non_cve_data = prepare_non_cve_data(vuln)
                cursor.execute(insert_query, non_cve_data)

            # Commit the transaction
            connection.commit()
            print("[+] Vulnerability inserted successfully into database.")

    except mysql.connector.Error as e:
        print(f"[-] MySQL Error: {e}")
    except Exception as e:
        print(f"[-] General Error: {e}")
    finally:
        if connection.is_connected():
            cursor.close()
            connection.close()
            print("[+] Closed the MySQL connection.")


# Insert an email into the SQL output database
def insert_email_data(emails, org_name):
    connection = mysql.connector.connect(**db_config)
    if connection.is_connected():
        cursor = connection.cursor()
        cursor.execute(f"USE {org_name}")
        for email in emails:
            email = email.strip()
            sql_query = "INSERT INTO email_input (email) VALUES (%s)"
            val = (email,)
            cursor.execute(sql_query, val)
            connection.commit()
        connection.close()

# Insert a breaches email into the SQL output database
def insert_breached_email_data(email_breaches, org_name):
    connection = mysql.connector.connect(**db_config)
    if connection.is_connected():
        cursor = connection.cursor()
        cursor.execute(f"USE {org_name}")
        for email_breach in email_breaches:
            sql_query = "INSERT INTO email_leaks (email, breach_name, breach_date, domain) VALUES (%s, %s, %s, %s)"
            val = (email_breach[0], email_breach[1], email_breach[2], email_breach[3])
            cursor.execute(sql_query, val)
            connection.commit()
        connection.close()

# Insert a leaked password into the SQL output database
def insert_password_data(passwords, org_name):
    connection = mysql.connector.connect(**db_config)
    if connection.is_connected():
        cursor = connection.cursor()
        cursor.execute(f"USE {org_name}")
        for password in passwords:
            sql_query = "INSERT INTO password_leaks (email, password) VALUES (%s, %s)"
            val = (password[0], password[1])
            cursor.execute(sql_query, val)
            connection.commit()
        connection.close()