#sudo venv/bin/python pktdetector.py

import requests
target="autoinnova.me"
while True:
    r=requests.get(f"https://{target}/")
    print(r.status_code)