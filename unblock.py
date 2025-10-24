import os

class Unblock:
    @staticmethod
    def unblock_ip(ip_address):
        chains = ["INPUT", "OUTPUT"]
        table = "filter"  
        for chain in chains:
            while True:
                
                result = os.popen(f"sudo iptables -t {table} -L {chain} --line-numbers -n | grep {ip_address}").read()
                if not result:
                    break
                num = result.split()[0] 
                os.system(f"sudo iptables -t {table} -D {chain} {num}")
        print(f"Unblocked all rules for IP: {ip_address}")
