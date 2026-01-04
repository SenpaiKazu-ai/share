import requests
import json
import os
import re
import sys
import time
import random
import string
import threading
from getuseragent import UserAgent
from rich import print as rich_print
from concurrent.futures import ThreadPoolExecutor

# Enhanced color palette
darkblue = "\033[34m"
green = "\033[1;32m"
red = "\033[1;31m"
yellow = "\033[1;33m"
skyblue = "\033[1;36m"
blue = "\033[1;34m"
lightblue = "\033[38;5;81m"
white = "\033[1;37m"
R = "\033[31m"
G = "\033[32m"
Y = "\033[33m"
B = "\033[34m"
M = "\033[35m"
P = "\033[36m"
C = "\033[37m"
LIGHT_GREEN = "\033[92m"
YELLOW_BRIGHT = "\033[93m"
NEON_PINK = "\033[38;5;213m"
NEON_CYAN = "\033[38;5;51m"
NEON_GREEN = "\033[38;5;46m"
PURPLE = "\033[38;5;135m"
RESET = "\033[0m"

ACCOUNTS_DIR = os.path.join(os.path.dirname(__file__), 'accounts')
CODE_FILE = os.path.join(ACCOUNTS_DIR, 'generated_code.txt')
COOKIES_FILE = os.path.join(ACCOUNTS_DIR, 'cookies.txt')
TOKENS_FILE = os.path.join(ACCOUNTS_DIR, 'tokens.txt')


def ensure_file_exists():
    """Ensure that the accounts directory and the code file exist by creating them if they don't exist."""
    os.makedirs(ACCOUNTS_DIR, exist_ok=True)
    open(CODE_FILE, 'a').close()  # This will create the file if it doesn't exist, but won't modify it.

def generate_code():
    """Generate a unique code in the format SAMMY-XXX-XXXXX."""
    prefix = "SAMMY"
    number_part = ''.join(random.choices(string.digits, k=3))  # 3 random digits
    letters_part = ''.join(random.choices(string.ascii_uppercase + string.digits, k=5))  # 5 alphanumeric characters
    code = f"{prefix}-{number_part}-{letters_part}"
    return code
   

def save_code(code):
    """Save the generated code to a file."""
    with open(CODE_FILE, 'w') as file:
        file.write(code)

def load_code():
    """Load the code from the file, if it exists."""
    if os.path.exists(CODE_FILE):
        with open(CODE_FILE, 'r') as file:
            return file.read().strip()
    return None

def is_code_approved(code):
    """Check if the generated code is approved by fetching the approval list."""
    try:
        # Use the correct raw GitHub URL for the Approval file
        url = "https://raw.githubusercontent.com/SenpaiKazu-ai/approve/refs/heads/main/approval"
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        approved_codes = response.text.splitlines()
        # Normalize lines: strip whitespace and ignore comments
        approved_codes = [line.split('#', 1)[0].strip() for line in approved_codes if line and not line.strip().startswith('#')]
        return code in approved_codes
    except requests.RequestException as e:
        print(f"Error fetching the approval list: {e}")
        # If we cannot reach GitHub, be conservative and return False
        return False


def generate_and_check_code():
    """Generate a code if not existing, check if it's approved, then return True/False."""
    ensure_file_exists()  # Ensure the code file exists before proceeding
    
    code = load_code()
    
    if code is None or code == '':

        code = generate_code()

        save_code(code)
        clear()       
        print(f"      {yellow}YOUR GENERATED CODE {white}: {red}{code}")
    else:
        clear()
        print(f"     {yellow}YOUR CODE {white}: {red}{code}")

    if is_code_approved(code):
        # Approved -> allow caller to continue
        return True
    else:
        # Not approved -> block access and inform user
        print(f"     {red}───────────────────────────────────────────────────────────────\033[0m")
        print(f"     {red}CODE IS NOT APPROVED ! {yellow}PLEASE SEND IT TO {white}: {yellow}https://www.facebook.com/sammy.trisha01")
        return False
def conver_to_cookie(user, passw, timeout=10, retries=1, proxy=None):
	user_agents = [
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Linux; Android 10; K) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36",
		"Mozilla/5.0 (iPhone; CPU iPhone OS 14_7_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Mobile/15E148 Safari/604.1",
		"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	]
	
	for attempt in range(retries):
		try:
			session = requests.Session()
			session.headers.update({'Accept-Encoding': 'gzip, deflate'})
			if proxy:
				session.proxies.update({'http': proxy, 'https': proxy})
			
			selected_ua = random.choice(user_agents)
			headers = {
				'authority': 'free.facebook.com',
				'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
				'accept-language': 'en-US,en;q=0.9',
				'cache-control': 'no-cache',
				'content-type': 'application/x-www-form-urlencoded',
				'pragma': 'no-cache',
				'origin': 'https://free.facebook.com',
				'referer': 'https://free.facebook.com/login/',
				'sec-fetch-dest': 'document',
				'sec-fetch-mode': 'navigate',
				'sec-fetch-site': 'same-origin',
				'sec-fetch-user': '?1',
				'upgrade-insecure-requests': '1',
				'user-agent': selected_ua,
			}
			
			# Get login page
			getlog = session.get('https://free.facebook.com/login.php', timeout=timeout, headers=headers, allow_redirects=True)
			page_text = getlog.text
			
			# Extract form fields with multiple patterns
			input_fields = re.findall(r'<input[^>]*?name=["\']([^"\']+)["\'][^>]*?value=["\']([^"\']*)["\']', page_text)
			input_dict = {k: v for k, v in input_fields}
			
			# Try alternative pattern
			if len(input_dict) < 3:
				input_fields = re.findall(r'name=["\']([^"\']+)["\'].*?value=["\']([^"\']*)["\']', page_text, re.DOTALL)
				input_dict.update({k: v for k, v in input_fields})
			
			# Build login payload with all extracted fields
			idpass = dict(input_dict)
			idpass['email'] = user
			idpass['pass'] = passw
			
			# Ensure login button is included
			if 'login' not in idpass:
				idpass['login'] = 'Log In'
			
			# Submit login
			comp = session.post(
				'https://free.facebook.com/login/device-based/regular/login/?shbl=1&refsrc=deprecated',
				headers=headers,
				data=idpass,
				allow_redirects=True,
				timeout=timeout
			)
			
			cookies_dict = session.cookies.get_dict()
			
			if 'c_user' in cookies_dict:
				# Login successful - now extract EAAG token immediately
				time.sleep(1)
				token_response = session.get('https://business.facebook.com/content_management', timeout=timeout, headers=headers)
				token_page = token_response.text
				
				if 'EAAG' in token_page:
					try:
						token = token_page.split('EAAG')[1].split('","')[0]
						if token and len(token) > 10:
							cookie_str = ";".join([f"{k}={v}" for k, v in cookies_dict.items()])
							return {"a": True, "b": f'{cookie_str}|EAAG{token}', "email": user}
					except:
						pass
				
				# Fallback: return cookie without token
				cookie_str = ";".join([f"{k}={v}" for k, v in cookies_dict.items()])
				return {"a": True, "b": cookie_str, "email": user}
			elif 'checkpoint' in cookies_dict:
				return {"a": False, "b": ":red-background[error] Account checkpoint", "email": user}
			elif comp.status_code in [200, 302] and cookies_dict:
				cookie_str = ";".join([f"{k}={v}" for k, v in cookies_dict.items()])
				return {"a": True, "b": cookie_str, "email": user}
			
			return {"a": False, "b": ":red-background[error] Invalid credentials", "email": user}
				
		except Exception as ed:
			if attempt < retries - 1:
				time.sleep(random.uniform(3, 6))
				continue
			return {"a": False, "b": f'Exception: {str(ed)[:40]}', "email": user}
def ban():
   print(f"""
{NEON_PINK}╔════════════════════════════════════════════════════════════╗
║                                                                       ║
║     ███████╗██╗  ██╗ █████╗ ██████╗ ███████╗ ██████╗                  ║
║     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝                  ║
║     ███████╗███████║███████║██████╔╝█████╗  ██║                       ║
║     ╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝  ██║                       ║
║     ███████║██║  ██║██║  ██║██║  ██║███████╗╚██████╗                  ║
║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝                  ║
║                                                                       ║
║ {NEON_CYAN}⚠️  CODE NOT APPROVED - ACCESS DENIED{NEON_PINK}           ║
║                                                                       ║
╚════════════════════════════════════════════════════════════╝
{NEON_CYAN}
Coded By: CASWELL CALEV
Programming Language: Python
{RESET}""")

def clear():
    if(sys.platform.startswith('win')):
        os.system('cls')
    else:
        os.system('clear')

gome_token = []

def tokz(input_cookies):
    extracted_tokens = []
    for idx, cookie in enumerate(input_cookies, 1):
        header_ = {
            'authority': 'business.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9',
            'accept-language': 'vi-VN,vi;q=0.9,fr-FR;q=0.8,fr;q=0.7,en-US;q=0.6,en;q=0.5',
            'cache-control': 'max-age=0',
            'cookie': cookie,
            'referer': 'https://www.facebook.com/',
            'sec-ch-ua': '".Not/A)Brand";v="99", "Google Chrome";v="103", "Chromium";v="103"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"Linux"',
            'sec-fetch-dest': 'document',
            'sec-fetch-mode': 'navigate',
            'sec-fetch-site': 'same-origin',
            'sec-fetch-user': '?1',
            'upgrade-insecure-requests': '1',
        }
        try:
            response = requests.get('https://business.facebook.com/content_management', headers=header_, timeout=10)
            home_business = response.text
            
            if response.status_code != 200:
                print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} HTTP Error {response.status_code}')
                continue
            
            if 'EAAG' not in home_business:
                if 'login' in home_business.lower() or 'checkpoint' in home_business.lower():
                    print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Checkpoint/Auth required')
                else:
                    print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} No token found')
                continue
            
            token = home_business.split('EAAG')[1].split('","')[0]
            if not token or len(token) < 10:
                print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Invalid token')
                continue
            
            cookie_token = f'{cookie}|EAAG{token}'
            gome_token.append(cookie_token)
            extracted_tokens.append((idx, cookie_token))
            print(f'{NEON_GREEN}[{idx}] ✓{RESET} Token extracted')
        except requests.RequestException as e:
            print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Network error')
        except IndexError:
            print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Parsing failed')
        except Exception as e:
            print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Error')
    return extracted_tokens

def save_tokens_to_file(extracted_tokens):
    """Save extracted tokens with line numbers to a file."""
    with open(TOKENS_FILE, 'w') as file:
        for line_num, token in extracted_tokens:
            file.write(f'{line_num}|{token}\n')
    print(f'\x1b[38;2;173;255;47m[+] \x1b[38;2;233;233;233mTokens saved to {TOKENS_FILE}')

def load_tokens_from_file():
    """Load tokens from file with line numbers."""
    if os.path.exists(TOKENS_FILE):
        tokens = []
        with open(TOKENS_FILE, 'r') as file:
            for line in file:
                line = line.strip()
                if line:
                    tokens.append(line)
        return tokens
    return []

def load_cookies_from_file(file_path):
    """Load cookies from a text file."""
    if os.path.exists(file_path):
        with open(file_path, 'r') as file:
            cookies = [line.strip() for line in file if line.strip()]
        return cookies
    else:
        print(f'\x1b[38;2;173;255;47m[!] \x1b[38;2;233;233;233mFile not found: {file_path}')
        return []

def extract_token_menu():
    """Menu for extracting tokens from a single cookie line."""
    clear()
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ████████╗ ██████╗ ██╗  ██╗███████╗███╗   ██╗███████╗       ║
║    ╚══██╔══╝██╔═══██╗██║ ██╔╝██╔════╝████╗  ██║██╔════╝       ║
║       ██║   ██║   ██║█████╔╝ █████╗  ██╔██╗ ██║███████╗       ║
║       ██║   ██║   ██║██╔═██╗ ██╔══╝  ██║╚██╗██║╚════██║       ║
║       ██║   ╚██████╔╝██║  ██╗███████╗██║ ╚████║███████║       ║
║       ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝╚══════╝       ║
║                                                               ║
║    {NEON_CYAN}Extract Token From Cookie{NEON_PINK}                                  ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")
    print(f"{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{NEON_CYAN}║{RESET} {NEON_GREEN}[1]{RESET} 📂 Load tokens from file                                  {NEON_CYAN}║{RESET}")
    print(f"{NEON_CYAN}║{RESET} {NEON_GREEN}[2]{RESET} ✏️  Paste your cookie manually                             {NEON_CYAN}║{RESET}")
    print(f"{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}")
    choice = input(f"{NEON_GREEN}➤ Select option: {RESET}").strip()
    
    if choice == '1':
        file_path = input(f"{NEON_GREEN}➤ Enter file path: {RESET}").strip()
        if not file_path:
            print(f'{NEON_PINK}[!]{RESET} No file path provided.')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
        
        cookies = load_cookies_from_file(file_path)
        if not cookies:
            print(f'{NEON_PINK}[!]{RESET} No cookies found in file.')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
        
        print(f'{NEON_GREEN}[*]{RESET} Extracting tokens from {NEON_CYAN}{len(cookies)}{RESET} cookies...')
        print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
        
        extracted = tokz(cookies)
        
        if extracted:
            save_tokens_to_file(extracted)
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_GREEN}[✓]{RESET} Tokens saved successfully!')
            all_tokens = load_tokens_from_file()
            print(f'{NEON_GREEN}[+]{RESET} Available tokens: {NEON_CYAN}{len(all_tokens)}{RESET}')
        else:
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_PINK}[!]{RESET} Failed to extract tokens.')
    
    elif choice == '2':
        cookie = input(f"{NEON_GREEN}➤ Paste your cookie: {RESET}").strip()
        
        if not cookie:
            print(f'{NEON_PINK}[!]{RESET} No cookie provided.')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
        
        print(f'{NEON_GREEN}[*]{RESET} Extracting token...')
        print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
        
        extracted = tokz([cookie])
        
        if extracted:
            save_tokens_to_file(extracted)
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_GREEN}[✓]{RESET} Token saved successfully!')
            all_tokens = load_tokens_from_file()
            print(f'{NEON_GREEN}[+]{RESET} Available tokens: {NEON_CYAN}{len(all_tokens)}{RESET}')
        else:
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_PINK}[!]{RESET} Failed to extract token.')
    else:
        print(f'{NEON_PINK}[!]{RESET} Invalid option.')
    
    input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')

def extract_cookies_menu():
    """Menu for extracting cookies from username/password credentials."""
    clear()
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ██████╗ ██████╗ ██╗  ██╗██╗███████╗███████╗        ║
║    ██╔════╝██╔═══██╗██╔══██╗██║ ██╔╝██║██╔════╝██╔════╝       ║
║    ██║     ██║   ██║██║  ██║█████╔╝ ██║█████╗  ███████╗       ║
║    ██║     ██║   ██║██║  ██║██╔═██╗ ██║██╔══╝  ╚════██║       ║
║    ╚██████╗╚██████╔╝██████╔╝██║  ██╗██║███████╗███████║       ║
║     ╚═════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝╚══════╝╚══════╝       ║
║                                                               ║
║     {NEON_CYAN}Extract Cookies From Credentials{NEON_PINK}    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")
    print(f"{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{NEON_CYAN}║{RESET} {NEON_GREEN}[1]{RESET} 📂 Load from file                                      {NEON_CYAN}║{RESET}")
    print(f"{NEON_CYAN}║{RESET} {NEON_GREEN}[2]{RESET} ⌨️  Enter manually                                      {NEON_CYAN}║{RESET}")
    print(f"{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}")
    choice = input(f"{NEON_GREEN}➤ Select option: {RESET}").strip()
    
    credentials = []
    
    if choice == '1':
        file_path = input(f"{NEON_GREEN}➤ Enter file path (email:password format): {RESET}").strip()
        if not file_path:
            print(f'{NEON_PINK}[!]{RESET} No file path provided.')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
        
        if os.path.exists(file_path):
            with open(file_path, 'r') as file:
                credentials = [line.strip() for line in file if line.strip() and ':' in line]
        else:
            print(f'{NEON_PINK}[!]{RESET} File not found.')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
    
    elif choice == '2':
        cred_input = input(f"{NEON_GREEN}➤ Enter credentials (email:password): {RESET}").strip()
        if ':' not in cred_input:
            print(f'{NEON_PINK}[!]{RESET} Invalid format. Use email:password')
            input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
            return
        credentials = [cred_input]
    else:
        print(f'{NEON_PINK}[!]{RESET} Invalid option.')
        input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
        return
    
    if not credentials:
        print(f'{NEON_PINK}[!]{RESET} No credentials found.')
        input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
        return
    
    print(f'{NEON_GREEN}[*]{RESET} Extracting cookies from {NEON_CYAN}{len(credentials)}{RESET} accounts...')
    print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
    
    extracted_cookies = []
    for idx, cred in enumerate(credentials, 1):
        try:
            email, password = cred.split(':', 1)
            result = conver_to_cookie(email.strip(), password.strip(), timeout=15, retries=2)
            
            if result['a']:
                extracted_cookies.append(result['b'])
                print(f'{NEON_GREEN}[{idx}] ✓{RESET} Cookie extracted for {NEON_CYAN}{email}{RESET}')
            else:
                print(f'{NEON_PINK}[{idx}] ✗{RESET} {result["b"]}')
        except Exception as e:
            print(f'{NEON_PINK}[{idx}] ✗{RESET} Error: {str(e)[:50]}')
    
    if extracted_cookies:
        print(f'{NEON_GREEN}[*]{RESET} Validating cookies...')
        valid_cookies = []
        for idx, cookie in enumerate(extracted_cookies, 1):
            if validate_cookie(cookie):
                valid_cookies.append(cookie)
                print(f'{NEON_GREEN}[{idx}] ✓{RESET} Cookie is valid')
            else:
                print(f'{NEON_PINK}[{idx}] ✗{RESET} Cookie is invalid or expired')
        
        if valid_cookies:
            with open(COOKIES_FILE, 'a') as file:
                for cookie in valid_cookies:
                    file.write(cookie + '\n')
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_GREEN}[✓]{RESET} {NEON_CYAN}{len(valid_cookies)}/{len(extracted_cookies)}{RESET} valid cookies saved to {NEON_GREEN}{COOKIES_FILE}{RESET}')
        else:
            print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
            print(f'{NEON_PINK}[!]{RESET} No valid cookies to save.')
    else:
        print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
        print(f'{NEON_PINK}[!]{RESET} No cookies extracted.')
    
    input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')

def validate_cookie(cookie):
    """Check if a cookie is valid by verifying it has required Facebook session cookies."""
    try:
        # Check if cookie contains required login indicators
        required_cookies = ['c_user', 'xs']
        has_required = all(f'{rc}=' in cookie for rc in required_cookies)
        
        if not has_required:
            return False
        
        headers = {
            'authority': 'business.facebook.com',
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
            'cookie': cookie,
            'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        }
        response = requests.get('https://business.facebook.com/content_management', headers=headers, timeout=5)
        
        # Check if response indicates logged-in state
        if response.status_code == 200:
            if 'EAAG' in response.text:
                return True
            elif 'login' in response.text.lower() or 'checkpoint' in response.text.lower():
                return False
        
        return False
    except:
        return False

def menu():
    clear()
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ███████╗█████╗ ███╗   ███╗███╗   ███╗██╗   ██╗███████╗     ║
║    ██╔════╝██╔══██╗████╗ ████║████╗ ████║╚██╗ ██╔╝██╔════╝    ║
║    ███████╗███████║██╔████╔██║██╔████╔██║ ╚████╔╝ ███████╗    ║
║    ╚════██║██╔══██║██║╚██╔╝██║██║╚██╔╝██║  ╚██╔╝  ╚════██║    ║
║    ███████║██║  ██║██║ ╚═╝ ██║██║ ╚═╝ ██║   ██║   ███████║    ║
║    ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚═╝     ╚═╝   ╚═╝   ╚══════╝    ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝

{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[1]{RESET} ⚡ Fast Mode      {NEON_GREEN}Share posts at high speed{RESET}               {NEON_CYAN}║{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[2]{RESET} 🐌 Slow Mode      {NEON_GREEN}Share with delays (safer){RESET}               {NEON_CYAN}║{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[3]{RESET} 🔑 Extract Token  {NEON_GREEN}Extract tokens from cookies{RESET}             {NEON_CYAN}║{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[4]{RESET} 🍪 Extract Cookie {NEON_GREEN}Generate cookies from accounts{RESET}          {NEON_CYAN}║{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[5]{RESET} 🗑️  Remove Dead    {NEON_GREEN}Remove invalid cookie/tokens{RESET}           {NEON_CYAN}║{RESET}
{NEON_CYAN}║{RESET} {NEON_GREEN}[6]{RESET} 🔄 Reset All      {NEON_GREEN}Clear all files & start fresh{RESET}           {NEON_CYAN}║{RESET}
{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}
{RESET}""")
    choice = input(f"{NEON_GREEN}➤ Select mode: {RESET}")
    return choice

def shar():
    choice = menu()
    
    if choice == '3':
        extract_token_menu()
        return
    elif choice == '4':
        extract_cookies_menu()
        return
    elif choice == '5':
        remove_dead_cookies()
        return
    elif choice == '6':
        reset_all_files()
        return
    
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║     ███████╗██╗  ██╗ █████╗ ██████╗ ███████╗ ██████╗          ║
║     ██╔════╝██║  ██║██╔══██╗██╔══██╗██╔════╝██╔════╝          ║
║     ███████╗███████║███████║██████╔╝█████╗  ██║               ║
║     ╚════██║██╔══██║██╔══██║██╔══██╗██╔══╝  ██║               ║
║     ███████║██║  ██║██║  ██║██║  ██║███████╗╚██████╗          ║
║     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝          ║
║                                                               ║
║        {NEON_CYAN}Coded By: CASWELL CALEV | Python{NEON_PINK}                       ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")
    
    all = load_tokens_from_file()
    
    if not all:
        print(f'{NEON_PINK}[!]{RESET} No tokens found. Extract tokens first using option 3.')
        input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
        return
    
    id_share = input(f"{NEON_GREEN}➤ Enter Post ID: {RESET}")
    total_share = int(input(f"{NEON_GREEN}➤ How Many Shares: {RESET}"))
    delay = int(input(f"{NEON_GREEN}➤ Delay Between Shares (seconds): {RESET}"))
    print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
    
    total_live = len(all)
    print(f'{NEON_GREEN}[+]{RESET} Loaded: {NEON_CYAN}{total_live}{RESET} Tokens')
    print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
    
    failed_tokens = []
    successful_shares = 0
    stt = 0
    
    if choice == '1':
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {}
            for _ in range(total_share):
                token_entry = all[stt % total_live]
                stt += 1
                cookie_token = '|'.join(token_entry.split('|')[1:])
                future = executor.submit(share, cookie_token, id_share)
                futures[future] = (token_entry, cookie_token)
                print(f'{NEON_GREEN}[⚡]{RESET} Attempted: {NEON_CYAN}{stt}/{total_share}{RESET}', end='\r')
                time.sleep(0.1)  # Small delay to avoid overwhelming the API
            
            for future in futures:
                token_entry, cookie_token = futures[future]
                result = future.result()
                if result:
                    successful_shares += 1
                else:
                    failed_tokens.append(token_entry)
    else:
        stt = 0
        while stt < total_share:
            for token_entry in all:
                if stt >= total_share:
                    break
                stt = stt + 1
                cookie_token = '|'.join(token_entry.split('|')[1:])
                result = share(cookie_token, id_share)
                if result:
                    successful_shares += 1
                else:
                    failed_tokens.append(token_entry)
                print(f'{NEON_GREEN}[🐌]{RESET} Attempted: {NEON_CYAN}{stt}/{total_share}{RESET}', end='\r')
                time.sleep(delay)
    
    if failed_tokens:
        remaining_tokens = [token for token in all if token not in failed_tokens]
        with open(TOKENS_FILE, 'w') as file:
            for token in remaining_tokens:
                file.write(token + '\n')
    
    print(f'\n{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
    print(f'{NEON_CYAN}║{RESET} {NEON_GREEN}✓ Successful Shares{RESET}: {NEON_GREEN}{successful_shares}{RESET}' + ' ' * (50 - len(str(successful_shares))) + f'{NEON_CYAN}║{RESET}')
    print(f'{NEON_CYAN}║{RESET} {NEON_PINK}✗ Failed Shares{RESET}: {NEON_PINK}{len(failed_tokens)}{RESET}' + ' ' * (55 - len(str(len(failed_tokens)))) + f'{NEON_CYAN}║{RESET}')
    print(f'{NEON_CYAN}║{RESET} {NEON_GREEN}! Remaining Tokens{RESET}: {NEON_GREEN}{len(all) - len(failed_tokens)}{RESET}' + ' ' * (50 - len(str(len(all) - len(failed_tokens)))) + f'{NEON_CYAN}║{RESET}')
    print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
    
    gome_token.clear()
    input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')

def share(cookie_token, post_id):
    """Share a post using the provided token."""
    try:
        parts = cookie_token.split('|')
        if len(parts) < 2:
            print(f'{NEON_PINK}[!]{RESET} Invalid token format')
            return False
        
        cookie = parts[0]
        token = parts[1]
        
        headers = {
            'accept': '*/*',
            'accept-encoding': 'gzip, deflate',
            'connection': 'keep-alive',
            'content-length': '0',
            'cookie': cookie,
            'host': 'graph.facebook.com'
        }
        
        response = requests.post(
            f'https://graph.facebook.com/me/feed?link=https://m.facebook.com/{post_id}&published=0&access_token={token}',
            headers=headers,
            timeout=10
        )
        
        if response.status_code == 200:
            print(f'{NEON_GREEN}[✓]{RESET} Share successful')
            return True
        else:
            print(f'{NEON_PINK}[✗]{RESET} Share failed: {response.status_code}')
            return False
    except Exception as e:
        print(f'{NEON_PINK}[!]{RESET} Error: {str(e)[:50]}')
        return False    
def remove_dead_cookies():
    """Remove dead cookies and tokens by testing them."""
    clear()
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ███████╗███╗   ███╗ ██████╗ ██╗   ██╗███████╗      ║
║    ██╔══██╗██╔════╝████╗ ████║██╔═══██╗██║   ██║██╔════╝      ║
║    ██████╔╝█████╗  ██╔████╔██║██║   ██║██║   ██║███████╗      ║
║    ██╔══██╗██╔══╝  ██║╚██╔╝██║██║   ██║╚██╗ ██╔╝╚════██║      ║
║    ██║  ██║███████╗██║ ╚═╝ ██║╚██████╔╝ ╚████╔╝ ███████║      ║
║    ╚═╝  ╚═╝╚══════╝╚═╝     ╚═╝ ╚═════╝   ╚═══╝  ╚══════╝      ║
║                                                               ║
║     {NEON_CYAN}Remove Dead Cookies & Tokens{NEON_PINK}        ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")
    
    all_tokens = load_tokens_from_file()
    
    if not all_tokens:
        print(f'{NEON_PINK}[!]{RESET} No tokens found.')
        input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
        return
    
    print(f'{NEON_GREEN}[*]{RESET} Testing {NEON_CYAN}{len(all_tokens)}{RESET} tokens...')
    print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
    
    valid_tokens = []
    dead_count = 0
    
    for idx, token_entry in enumerate(all_tokens, 1):
        try:
            parts = token_entry.split('|')
            if len(parts) < 2:
                dead_count += 1
                print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Invalid format')
                continue
            
            cookie = parts[0]
            
            headers = {
                'authority': 'business.facebook.com',
                'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8',
                'cookie': cookie,
                'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            response = requests.get('https://business.facebook.com/content_management', headers=headers, timeout=5)
            
            if response.status_code == 200 and 'EAAG' in response.text:
                valid_tokens.append(token_entry)
                print(f'{NEON_GREEN}[{idx}] ✓{RESET} Token is valid')
            else:
                dead_count += 1
                print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Token is dead')
        except Exception as e:
            dead_count += 1
            print(f'{NEON_GREEN}[{idx}]{RESET} {NEON_PINK}✗{RESET} Error testing token')
    
    if valid_tokens:
        with open(TOKENS_FILE, 'w') as file:
            for token in valid_tokens:
                file.write(token + '\n')
        print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
        print(f'{NEON_GREEN}[✓]{RESET} Removed {NEON_PINK}{dead_count}{RESET} dead tokens')
        print(f'{NEON_GREEN}[+]{RESET} Remaining valid tokens: {NEON_CYAN}{len(valid_tokens)}{RESET}')
    else:
        with open(TOKENS_FILE, 'w') as file:
            file.write('')
        print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
        print(f'{NEON_PINK}[!]{RESET} All tokens are dead. File cleared.')
    
    input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')

def reset_all_files():
    """Reset and clean all stored files."""
    clear()
    print(f"""{NEON_PINK}
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║    ██████╗ ███████╗███████╗███████╗████████╗                  ║
║    ██╔══██╗██╔════╝██╔════╝██╔════╝╚══██╔══╝                  ║
║    ██████╔╝█████╗  ███████╗█████╗     ██║                     ║
║    ██╔══██╗██╔══╝  ╚════██║██╔══╝     ██║                     ║
║    ██║  ██║███████╗███████║███████╗   ██║                     ║
║    ╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝   ╚═╝                     ║
║                                                               ║
║         {NEON_CYAN}Reset & Clean All Files{NEON_PINK}         ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
{RESET}""")
    
    print(f'{NEON_GREEN}[!]{RESET} This will delete all stored:')
    print(f'{NEON_GREEN}    • Tokens{RESET}')
    print(f'{NEON_GREEN}    • Cookies{RESET}')
    print(f'{NEON_GREEN}    • Generated Code{RESET}')
    print()
    confirm = input(f'{NEON_GREEN}➤ Type "YES" to confirm: {RESET}').strip()
    
    if confirm.upper() != 'YES':
        print(f'{NEON_GREEN}[✓]{RESET} Reset cancelled.')
        input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')
        return
    
    try:
        # Clear tokens file
        if os.path.exists(TOKENS_FILE):
            open(TOKENS_FILE, 'w').close()
            print(f'{NEON_GREEN}[✓]{RESET} Tokens file cleared')
        
        # Clear cookies file
        if os.path.exists(COOKIES_FILE):
            open(COOKIES_FILE, 'w').close()
            print(f'{NEON_GREEN}[✓]{RESET} Cookies file cleared')
        
        # Clear code file
        if os.path.exists(CODE_FILE):
            open(CODE_FILE, 'w').close()
            print(f'{NEON_GREEN}[✓]{RESET} Code file cleared')
        
        print(f'{NEON_CYAN}╔═══════════════════════════════════════════════════════════════╗{RESET}')
        print(f'{NEON_GREEN}[✓]{RESET} All files have been reset successfully!')
        print(f'{NEON_CYAN}╚═══════════════════════════════════════════════════════════════╝{RESET}')
    except Exception as e:
        print(f'{NEON_PINK}[!]{RESET} Error during reset: {str(e)[:50]}')
    
    input(f'{NEON_CYAN}[*]{RESET} Press Enter to continue...{RESET}')

if __name__ == "__main__":
    if generate_and_check_code():
        shar()
    else:
        ban()