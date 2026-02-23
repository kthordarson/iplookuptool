import json
import requests
import argparse
import re
import os
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
urllib3.disable_warnings(urllib3.exceptions.SSLError)  # type: ignore

def get_urlhaus_data(args):
    url = 'https://urlhaus-api.abuse.ch/v1/host/'
    api_key = os.getenv("URLHAUS_API_KEY")
    
    headers = {
        'Auth-Key' : api_key,
    }
    json_data = {'host': args.ip}
    r = requests.post(url, json=json_data, timeout=15, headers=headers)
    print("Submission status: " + r.text)
