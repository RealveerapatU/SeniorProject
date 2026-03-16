# source .venv/bin/activate
import netifaces
import pyshark
import datetime
import pandas as pd
import os
inter= 'ens5'
capture = pyshark.LiveCapture(interface=inter)

class Statistics():
    @staticmethod
    def Logs(req_port, src_ip, dst_ip, pkt_time, syn_flag, ack_flag):
        current_datetime = datetime.datetime.today()
        day_of_week = current_datetime.strftime('%A')
        log_file = 'log.csv'

        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("Day,Time,Source IP,Destination IP,Destination Port,SYN Flag,ACK Flag\n")

        with open(log_file, 'a') as f:
            f.write(f"{day_of_week},{pkt_time},{src_ip},{dst_ip},{req_port},{syn_flag},{ack_flag}\n")

        Security.PortScanDetect()
        Security.DosDetect()

class Security():
    
    @staticmethod
    def DosDetect():
        
        today = datetime.datetime.today()
        myipaddress = netifaces.ifaddresses(inter)[netifaces.AF_INET][0]['addr']
        df = pd.read_csv('log.csv')
        baseline_weekend=df[(df['Day'].isin(['Saturday', 'Sunday'])) & (df['Destination Port'] != 22)]
        baseline_weekday=df[(df['Day'].isin(['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday'])) & (df['Destination Port'] != 22)]
        block_file = 'Block.csv'
        if not os.path.exists(block_file):
         with open(block_file, 'w') as f:
            f.write("Source IP\n")

        if(today.strftime('%A') in ['Saturday', 'Sunday']):
         threshold = 12 *  baseline_weekend.groupby('Source IP').size().mean()
         byip=baseline_weekend.groupby('Source IP')
         for ip, count in byip.size().items():
            if count > threshold and ip !=myipaddress:
                dfblock = pd.read_csv(block_file)
                if ip not in dfblock['Source IP'].values:
                    Iptables.block_ip(ip)
                    print("DoS attack detected from:", ip)
         
        else:
         threshold = 12 *  baseline_weekday.groupby('Source IP').size().mean()
         byip=baseline_weekday.groupby('Source IP')
         for ip, count in byip.size().items():
            if count > threshold and ip !=myipaddress:
                dfblock = pd.read_csv(block_file)
                if ip not in dfblock['Source IP'].values:
                    Iptables.block_ip(ip)
                    print("DoS attack detected from:", ip)

       
   
    @staticmethod
    def PortScanDetect():
        myipaddress = netifaces.ifaddresses(inter)[netifaces.AF_INET][0]['addr']
        df = pd.read_csv('log.csv')
        df = df[['Source IP', 'Destination Port']]
        byip = df.groupby('Source IP')
        request_ports = byip['Destination Port'].nunique()
        ##  real
        # threshold = 300
        ##For testing  15
        threshold = 50

        log_file = 'Block.csv'
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("Source IP\n")

        dfportblock = pd.read_csv(log_file)

        for ip, port in request_ports.items():
            if port > threshold and ip !=myipaddress:
                if ip not in dfportblock['Source IP'].values:
                    Iptables.block_ip(ip)
                    print("Port scanning detected from:", ip)
               

class Iptables:
    @staticmethod
    def block_ip(ip_address):
        command_input = f"sudo iptables -I INPUT -s {ip_address} -j DROP"
        command_output = f"sudo iptables -I OUTPUT -d {ip_address} -j DROP"
        os.system(command_input)
        os.system(command_output)
        log_file = 'Block.csv'
       
        if not os.path.exists(log_file):
            with open(log_file, 'w') as f:
                f.write("Source IP\n")
        
        dfportblock = pd.read_csv(log_file)
        if ip_address not in dfportblock['Source IP'].values:
            with open(log_file, 'a') as f:
             f.write(f"{ip_address}\n")
             print(f"Blocked IP: {ip_address}")
             

    @staticmethod
    def unblock_ip(ip_address):
        chains = ["INPUT", "OUTPUT"]
        table = "filter"
        for chain in chains:
            result = os.popen(f"sudo iptables -t {table} -L {chain} --line-numbers -n | grep {ip_address}").read()
            if result:
                lines = result.strip().split('\n')
                nums = [int(line.split()[0]) for line in lines]
                for num in sorted(nums, reverse=True):
                    os.system(f"sudo iptables -t {table} -D {chain} {num}")
                    
                print(f"Unblocked all rules for IP {ip_address} in chain {chain}")

class Info:
    @staticmethod
    def packetdetector():
        print("Host Intruder detection and response system.Select mode to continue \n1.Packet Detector\n2.Unblock IP\n3.Statistics Analysis")
        input_mode = input("Enter mode number: ")
        if(input_mode =='1'):
            try:
                for packet in capture.sniff_continuously():
                    try:
                        if 'TCP' in packet:
                            source_address = packet.ip.src
                            source_port = packet.tcp.srcport
                            destination_address = packet.ip.dst
                            destination_port = packet.tcp.dstport
                            packet_time = packet.sniff_time

                            syn_flag = 1 if str(packet.tcp.flags_syn).lower() == 'true' else 0
                            ack_flag = 1 if str(packet.tcp.flags_ack).lower() == 'true' else 0

                            Statistics.Logs(destination_port, source_address, destination_address, packet_time, syn_flag, ack_flag)
                    except AttributeError:
                        pass
            except (KeyboardInterrupt, EOFError):
                print("Service Has been terminated")
                return

Info.packetdetector()
