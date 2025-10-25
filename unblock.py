import os

ip_address = input("Enter IP address to unblock: ")
chains = ["INPUT", "OUTPUT"]
table = "filter"

for chain in chains:
   
    result = os.popen(f"sudo iptables -t {table} -L {chain} --line-numbers -n | grep {ip_address}").read()
    if result:
        lines = result.strip().split('\n')
       
        nums = [int(line.split()[0]) for line in lines]
        for num in sorted(nums, reverse=True):
            os.system(f"sudo iptables -t {table} -D {chain} {num}")

print(f"Unblocked all rules for IP: {ip_address}")
