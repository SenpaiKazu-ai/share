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
darkblue = "\033[34m"
green = "\033[1;32m"
red = "\033[1;31m"
yellow = "\033[1;33m"
skyblue = "\033[1;36m"
blue = "\033[1;34m"
lightblue = "\033[38;5;81m"
white = "\033[1;37m"
R = "\033[31m"  # Red
G = "\033[32m"  # Green
Y = "\033[33m"  # Yellow
B = "\033[34m"  # Blue
M = "\033[35m"  # Magenta
P = "\033[36m"  # Cyan
C = "\033[37m"  # White
LIGHT_GREEN = "\033[92m"   # bright/light green
YELLOW_BRIGHT = "\033[93m" # bright yellow
ACCOUNTS_DIR = os.path.join(os.path.dirname(__file__), 'accounts')
CODE_FILE = os.path.join(ACCOUNTS_DIR, 'generated_code.txt')

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
def ban():
   print("""
\033[1;38;2;255;105;180m   

╔═╗╦ ╦╔╦╗╔═╗  ╔═╗╦ ╦╔═╗╦═╗╔═╗
╠═╣║ ║ ║ ║ ║  ╚═╗╠═╣╠═╣╠╦╝║╣ 
╩ ╩╚═╝ ╩ ╚═╝  ╚═╝╩ ╩╩ ╩╩╚═╚═╝

\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
Coded By: CASWELL CALEV
\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
\033[0m""")

def clear():
    if(sys.platform.startswith('win')):
        os.system('cls')
    else:
        os.system('clear')

gome_token = []

def tokz(input_cookies):
    for cookie in input_cookies:
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
            home_business = requests.get('https://business.facebook.com/content_management', headers=header_, timeout=10).text
            token = home_business.split('EAAG')[1].split('","')[0]
            cookie_token = f'{cookie}|EAAG{token}'
            gome_token.append(cookie_token)
        except Exception as e:
            print(f'Error extracting token: {e}')
    return gome_token

def share(tach, id_share):
    cookie = tach.split('|')[0]
    token = tach.split('|')[1]
    he = {
        'accept': '*/*',
        'accept-encoding': 'gzip, deflate',
        'connection': 'keep-alive',
        'content-length': '0',
        'cookie': cookie,
        'host': 'graph.facebook.com'
    }
    try:
        res = requests.post(f'https://graph.facebook.com/me/feed?link=https://m.facebook.com/{id_share}&published=0&access_token={token}', headers=he, timeout=10).json()
    except Exception as e:
        print(f'Error sharing: {e}')
    
def menu():
    clear()
    print("""
\033[1;38;2;255;105;180m   

╔═╗╦ ╦╔╦╗╔═╗  ╔═╗╦ ╦╔═╗╦═╗╔═╗
╠═╣║ ║ ║ ║ ║  ╚═╗╠═╣╠═╣╠╦╝║╣ 
╩ ╩╚═╝ ╩ ╚═╝  ╚═╝╩ ╩╩ ╩╩╚═╚═╝

\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
Coded By: CASWELL CALEV
\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
\033[0m""")
    print("\x1b[38;2;173;255;47m[1] \x1b[38;2;233;233;233mFast")
    print("\x1b[38;2;173;255;47m[2] \x1b[38;2;233;233;233mSlow")
    choice = input("\x1b[38;2;173;255;47mSelect mode: \x1b[38;2;233;233;233m")
    return choice

def shar():
    choice = menu()
    clear()
    print("""
\033[1;38;2;255;105;180m   

╔═╗╦ ╦╔╦╗╔═╗  ╔═╗╦ ╦╔═╗╦═╗╔═╗
╠═╣║ ║ ║ ║ ║  ╚═╗╠═╣╠═╣╠╦╝║╣ 
╩ ╩╚═╝ ╩ ╚═╝  ╚═╝╩ ╩╩ ╩╩╚═╚═╝

\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
Coded By: CASWELL CALEV
Programming Language use: Python
\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m
\033[0m""")
    input_cookies = input("\x1b[38;2;173;255;47mEnter Cookie:  \x1b[38;2;233;233;233m").split(',')
    id_share = input("\x1b[38;2;173;255;47mEnter Post ID: \x1b[38;2;233;233;233m")
    total_share = int(input("\x1b[38;2;173;255;47mHow Many Share: \x1b[38;2;233;233;233m"))
    delay = int(input("\x1b[38;2;173;255;47m Delay Share: \x1b[38;2;233;233;233m"))
    print('\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m')
    print('\x1b[38;2;173;255;47m[*] \x1b[38;2;233;233;233mwaiting...', end='\r')

    all = tokz(input_cookies)
    total_live = len(all)
    print(f'\x1b[38;2;173;255;47mLive: \x1b[38;2;233;233;233m{total_live} \x1b[38;2;173;255;47mCookies')
    
    if total_live == 0:
        print('\x1b[38;2;173;255;47m[!] \x1b[38;2;233;233;233mNo valid cookies found!')
        sys.exit()

    print('\x1b[38;2;173;255;47m════════════════════════════════════\x1b[38;2;233;233;233m')
    
    if choice == '1':
        stt = 0
        with ThreadPoolExecutor(max_workers=5) as executor:
            futures = []
            for _ in range(total_share):
                tach = all[stt % total_live]
                stt += 1
                futures.append(executor.submit(share, tach, id_share))
                print(f'\x1b[38;2;173;255;47mShare: + \x1b[38;2;233;233;233m{stt}', end='\r')
                time.sleep(delay)
            
            for future in futures:
                future.result()
    else:
        stt = 0
        while stt < total_share:
            for tach in all:
                if stt >= total_share:
                    break
                stt = stt + 1
                share(tach, id_share)
                print(f'\x1b[38;2;173;255;47mShare: + \x1b[38;2;233;233;233m{stt}', end='\r')
                time.sleep(delay)

    gome_token.clear()
    input('\x1b[38;2;173;255;47m[*] \x1b[38;2;233;233;233mEnter^^\033[0m')

if __name__ == '__main__':
     # Run approval flow first; only run main() when approved.
    allowed = generate_and_check_code()
    if not allowed:
        import sys
        sys.exit(1)
    shar()