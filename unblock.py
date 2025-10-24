import os

class Unblock:
    @staticmethod
    def unblock_ip():
        ip_address = input("Enter IP address to unblock: ")
        command_input = f"sudo iptables -D INPUT -s {ip_address} -j DROP"
        command_output = f"sudo iptables -D OUTPUT -d {ip_address} -j DROP"
        os.system(command_input)
        os.system(command_output)
        print(f"Unblocked IP: {ip_address}")

Unblock.unblock_ip()
