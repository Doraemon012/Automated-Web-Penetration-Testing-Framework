import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin
import time

class SessionManager:
    def __init__(self, base_url):
        self.base_url = base_url
        self.session = requests.Session()
        self.authenticated = False
        
    def login_form(self, login_url, username, password, username_field='username', password_field='password'):
        """
        Authenticate using form-based login
        """
        try:
            # Get login page to extract CSRF tokens or other hidden fields
            response = self.session.get(urljoin(self.base_url, login_url), timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')
            
            # Find login form
            login_form = soup.find('form')
            if not login_form:
                return False
                
            # Prepare login data
            login_data = {}
            
            # Extract hidden fields (CSRF tokens, etc.)
            for hidden_input in login_form.find_all('input', type='hidden'):
                name = hidden_input.get('name')
                value = hidden_input.get('value', '')
                if name:
                    login_data[name] = value
            
            # Add credentials
            login_data[username_field] = username
            login_data[password_field] = password
            
            # Submit login form
            action = login_form.get('action') or login_url
            login_url_full = urljoin(self.base_url, action)
            
            response = self.session.post(login_url_full, data=login_data, timeout=5)
            
            # Check if login was successful (basic heuristics)
            if response.status_code == 200:
                # Check for common success indicators
                success_indicators = ['dashboard', 'profile', 'logout', 'welcome']
                failure_indicators = ['error', 'invalid', 'incorrect', 'failed']
                
                response_text = response.text.lower()
                
                has_success = any(indicator in response_text for indicator in success_indicators)
                has_failure = any(indicator in response_text for indicator in failure_indicators)
                
                if has_success and not has_failure:
                    self.authenticated = True
                    print(f"[+] Successfully authenticated via form login")
                    return True
                    
            return False
            
        except requests.RequestException as e:
            print(f"[-] Login failed: {e}")
            return False
    
    def login_token(self, token, header_name='Authorization', token_prefix='Bearer'):
        """
        Authenticate using token-based authentication
        """
        try:
            if token_prefix:
                token_value = f"{token_prefix} {token}"
            else:
                token_value = token
                
            self.session.headers.update({header_name: token_value})
            
            # Test authentication by making a request to base URL
            response = self.session.get(self.base_url, timeout=5)
            
            if response.status_code in [200, 301, 302]:
                self.authenticated = True
                print(f"[+] Successfully authenticated via token")
                return True
                
            return False
            
        except requests.RequestException as e:
            print(f"[-] Token authentication failed: {e}")
            return False
    
    def login_basic_auth(self, username, password):
        """
        Authenticate using HTTP Basic Authentication
        """
        try:
            self.session.auth = (username, password)
            
            # Test authentication
            response = self.session.get(self.base_url, timeout=5)
            
            if response.status_code != 401:
                self.authenticated = True
                print(f"[+] Successfully authenticated via Basic Auth")
                return True
                
            return False
            
        except requests.RequestException as e:
            print(f"[-] Basic auth failed: {e}")
            return False
    
    def add_custom_headers(self, headers):
        """
        Add custom headers to session (API keys, etc.)
        """
        self.session.headers.update(headers)
    
    def get_session(self):
        """
        Return the authenticated session for use by scanners
        """
        return self.session
    
    def is_authenticated(self):
        """
        Check if session is authenticated
        """
        return self.authenticated
    
    def logout(self, logout_url=None):
        """
        Logout and clear session
        """
        if logout_url:
            try:
                self.session.get(urljoin(self.base_url, logout_url), timeout=5)
            except:
                pass
        
        self.session.close()
        self.authenticated = False
        print("[+] Session logged out")