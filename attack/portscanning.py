import socket

ip = input("Enter IP of the target: ")

for port in range(1, 65535):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
   
        if not s.connect_ex((ip, port)):
            print(f"Port {port} is open")
