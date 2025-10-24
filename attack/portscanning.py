import socket

ip = input("Enter IP of the target: ")

for port in range(1, 65536):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)  # เพิ่ม timeout
        if not s.connect_ex((ip, port)):
            print(f"Port {port} is open")
        else:
            print(f"Port {port} is closed")
