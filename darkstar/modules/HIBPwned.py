import time
from modules.recon import RequestsAPI, FindBreaches
from modules.db_helper import insert_email_data, insert_breached_email_data, insert_password_data
import random

#? response codes HTTP
SUCCES = 200
PAGE_NOT_FOUND = 404
TOO_MANY_CALLS = 429

# If true we scan for password leaks
PASSWORD_SCANNING = True

class HIBPwned:
    def __init__(self, email_file: str, org_name: str):
        self.org_name = org_name
        self.emails = []
        
        with open(email_file, "r") as file:
            self.emails = file.readlines()

    def run(self):
        # Initialize the RequestsAPI class
        api = RequestsAPI()

        # Initialize the FindBreaches class
        find_breaches = FindBreaches()

        # Loop through all the emails
        #? Store email in the database as email_input, as online discoverd emails
        insert_email_data(self.emails, self.org_name)

        for email in self.emails:
            email = email.strip()
            print(f"Checking email: {email}")
            while True:
                # Get the response from the HIBPwned API
                response = api.get_HIBPwned_request(email)
                if response.status_code == SUCCES:
                    breaches = find_breaches.find_email_breach(email, response.json())
                    #? Insert to the email_leaks table
                    insert_breached_email_data(breaches, self.org_name)
                    break
                elif response.status_code == TOO_MANY_CALLS:
                    x = random.randint(6, 20)
                    print(f"Too many calls, sleeping for {x} seconds")
                    time.sleep(x)
                elif response.status_code == PAGE_NOT_FOUND:
                    print("No breaches found")
                    break
                else:
                    print(f"Error: {response.status_code}")
                    break

            # If we are scanning for passwords
            if PASSWORD_SCANNING:
                while True:
                    # Get the response from the Proxynova API
                    response = api.get_proxynova_request(email)
                    if response.status_code == SUCCES:
                        passwords = find_breaches.find_passwords(email, response.text.splitlines())
                        #? Insert to the password_leaks table
                        insert_password_data(passwords, self.org_name)
                        break
                    elif response.status_code == TOO_MANY_CALLS:
                        x = random.randint(6, 20)
                        print(f"Too many calls, sleeping for {x} seconds")
                        time.sleep(x)
                    else:
                        print(f"Error: {response.status_code}")
                        break