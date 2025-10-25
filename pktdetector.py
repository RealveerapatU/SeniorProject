# source .venv/bin/activate
import netifaces
import pyshark
import datetime
import pandas as pd
import os
capture = pyshark.LiveCapture(interface='en1')

class Statistics():
    @staticmethod
    def Logs(req_port, src_ip, dst_ip, pkt_time, syn_flag, ack_flag):
        current_datetime = datetime.datetime.today()
        day_of_week = current_datetime.strftime('%A')
        with open('log.csv', 'a') as f:
            f.write(f"{day_of_week},{pkt_time},{src_ip},{dst_ip},{req_port},{syn_flag},{ack_flag}\n")
        Security.RequestStatistics()

class Security():
    syncflooding = False
    abnormaltraffic = False

    @staticmethod
    def RequestStatistics():
        read = pd.read_csv('log.csv', names=['Day', 'Time', 'Source IP', 'Destination IP', 'Destination Port', 'SYN Flag', 'ACK Flag'])
        df = pd.DataFrame(read)
        Security.DdosDetection(df['Day'], df['Time'], df['Source IP'], df['Destination IP'], df['Destination Port'], df)
        Security.PortScanDetect(df['Day'], df['Time'], df['Source IP'], df['Destination IP'], df['Destination Port'], df)

    @staticmethod
    def DdosDetection(Day, Time, Source_IP, Destination_IP, Destination_Port, df):
        today = datetime.datetime.today().strftime('%A')
        today_date = datetime.datetime.today().date()

        syncattack_ip=0

        day = Day.tolist()
        time = Time.tolist()

        normal_days = ['Monday', 'Tuesday', 'Wednesday', 'Thursday']
        weekend_days = ['Friday', 'Saturday', 'Sunday']

        if today in weekend_days:
            weekend_universe = sum(d in weekend_days for d in day)
            req_hour = weekend_universe / 24
        else:
            normal_universe = sum(d in normal_days for d in day)
            req_hour = normal_universe / 24

        today_requests = sum(
            datetime.datetime.strptime(str(t), '%Y-%m-%d %H:%M:%S.%f').date() == today_date
            if '.' in str(t)
            else datetime.datetime.strptime(str(t), '%Y-%m-%d %H:%M:%S').date() == today_date
            for t in time
        )

        print("Normal Request per hour:", req_hour)
        print("Total requests today:", today_requests)
        iface = 'en1'
        myip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        
        if (today_requests / 24) > req_hour * 100:
            
            Security.abnormaltraffic = True

        syn_counts = df[df['SYN Flag'] == 1]['Source IP'].value_counts()
        threshold = 100
        attackers = syn_counts[syn_counts > threshold]
        if not attackers.empty:
            Security.syncflooding = True
            for ip in attackers.index:
                syncattack_ip=ip
                if(syncattack_ip != myip):
                    print("Possible Dos attack form :", syncattack_ip)
                    BlockingIP().block_ip(syncattack_ip)
                    print(syncattack_ip,"Has been neutralized.")
                
                    
                
                
        else:
            print("No SYN Flood Attack Detected.")

        if(Security.syncflooding and Security.abnormaltraffic):
            print("Alert: Both SYN Flood and Abnormal Traffic Detected!")
            BlockingIP().block_ip(syncattack_ip)
    @staticmethod
    def PortScanDetect(Day, Time, Source_IP, Destination_IP, Destination_Port, df):
        portscan_ip = 0
        portscan_threshold = 50

        portscan_counts = df.groupby('Source IP')['Destination Port'].nunique()
        potential_portscanners = portscan_counts[portscan_counts > portscan_threshold]
        iface = 'en1'
        myip = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
        if not potential_portscanners.empty:
            for ip in potential_portscanners.index:
                if(ip != myip):
                 portscan_ip = ip
                 print(portscan_ip)
                 print("Possible Port Scanning Detected from IP(s):",portscan_ip)
                 BlockingIP().block_ip(portscan_ip)
        else:
            print("No Port Scanning Detected.")



class BlockingIP:
    @staticmethod
    def block_ip(ip_address):
       
      command_input = f"sudo iptables -I INPUT -s {ip_address} -j DROP"
      command_output = f"sudo iptables -I OUTPUT -d {ip_address} -j DROP"
      os.system(command_input)
      os.system(command_output)
      print(f"Blocked IP: {ip_address}")
     
class Info:
    @staticmethod
    def packetdetector():
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
            print("\nStopped packet capturing safely.")
            return

Info.packetdetector()
