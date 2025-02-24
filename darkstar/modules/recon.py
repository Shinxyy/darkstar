import requests
from modules.config import HIBP_KEY

class RequestsAPI:
    def __init__(self):
        self.APIKey = HIBP_KEY

    # Send/Receive HIBPwned request
    def get_HIBPwned_request(self, email):
        headers = {
            "hibp-api-key": self.APIKey
        }
        return requests.get(
            f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false",
            headers=headers
        )

    # Senc/Receive Proxynova request
    def get_proxynova_request(self, email):
        return requests.get(f"https://api.proxynova.com/comb?query={email}")

class WordPressDetector:
    def __init__(self, timeout=10):
        """
        Initialize the detector with an optional timeout for HTTP requests.
        """
        self.timeout = timeout

    def check_main_page(self, url):
        """
        Fetch the main page and search for common WordPress markers.
        """
        try:
            response = requests.get(url, timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if ("wp-content" in content or 
                    "wp-includes" in content or 
                    'meta name="generator" content="wordpress' in content):
                    return True
        except requests.RequestException:
            pass
        return False

    def check_wp_login(self, url):
        """
        Check if the /wp-login.php page exists and contains WordPress login hints.
        """
        try:
            response = requests.get(url + "/wp-login.php", timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if "wp-submit" in content or "loginform" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_readme(self, url):
        """
        Check if the /readme.html file exists and mentions WordPress.
        """
        try:
            response = requests.get(url + "/readme.html", timeout=self.timeout)
            if response.status_code == 200:
                content = response.text.lower()
                if "wordpress" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_xmlrpc(self, url):
        """
        Check if the /xmlrpc.php endpoint responds in a way that indicates a WordPress XML-RPC server.
        """
        try:
            response = requests.get(url + "/xmlrpc.php", timeout=self.timeout)
            if response.status_code in (200, 405):
                content = response.text.lower()
                if "xmlrpc" in content:
                    return True
        except requests.RequestException:
            pass
        return False

    def check_wp_json(self, url):
        """
        Check if the /wp-json/ endpoint exists and returns JSON with WordPress REST API keys.
        """
        try:
            response = requests.get(url + "/wp-json/", timeout=self.timeout)
            if response.status_code == 200:
                content_type = response.headers.get("content-type", "")
                if content_type.startswith("application/json"):
                    try:
                        data = response.json()
                        if "namespaces" in data or "routes" in data:
                            return True
                    except ValueError:
                        pass
        except requests.RequestException:
            pass
        return False

    def is_wordpress(self, url):
        """
        Run multiple tests on the given URL. If any test returns True,
        the site is assumed to be running WordPress.
        """
        tests = [
            self.check_main_page(url),
            self.check_wp_login(url),
            self.check_readme(url),
            self.check_xmlrpc(url),
            self.check_wp_json(url)
        ]
        # Uncomment below to see the outcome of each test:
        # print(f"Testing {url}: {tests} -> {sum(tests)} positive indicator(s)")
        return any(tests)

    def check_domain(self, domain):
        """
        Given a domain (without protocol), try HTTPS first and then HTTP.
        Returns True if any test indicates a WordPress site.
        """
        domain = domain.strip()
        if not domain:
            return False

        url_https = f"https://{domain}"
        url_http = f"http://{domain}"
        if self.is_wordpress(url_https):
            return True
        if self.is_wordpress(url_http):
            return True
        return False

    def run(self, filepath):
        """
        Reads a file containing domain names (one per line) and returns a list
        of those domains that appear to be running WordPress.
        """
        try:
            with open(filepath, 'r') as file:
                domains = [line.strip() for line in file if line.strip()]
        except Exception as e:
            print(f"Error reading file {filepath}: {e}")
            return []

        wordpress_domains = []
        for domain in domains:
            if self.check_domain(domain):
                wordpress_domains.append(domain)
        return ",".join(wordpress_domains)

class FindBreaches:
    # Handles all the breaches and returns a list with all the relevant information
    def find_email_breach(self, email, response):
        breaches = []
        # Parsing the response JSON
        data = response
        for info in data:
            breaches.append([email, info["Name"], info["BreachDate"], info["Domain"]])
        return breaches

    # Handles all the paswords found and returns a list with email/password combinations
    def find_passwords(self, email, response):
        truncated_passwords = []
        for line in response:
            count = line.find(email)
            #print(count)
            if count > 0:
                try:
                    password = line.split(email + ":")[1].split('"')[0]
                    print(f"Leaked Password found: {password}")
                    # Only return first 3 characters of password
                    truncated_passwords.append([email, password[:3]])
                except:
                    password = ""
                    # empty password
                    truncated_passwords.append([email, password])
                
        return truncated_passwords


    