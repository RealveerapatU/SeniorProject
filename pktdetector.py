import pyshark
import datetime
import pandas as pd

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

        if (today_requests / 24) > req_hour * 10:
            print("Possible DDoS Attack Detected!")
            abnormaltraffic = True

        syn_counts = df[df['SYN Flag'] == 1]['Source IP'].value_counts()
        threshold = 100
        attackers = syn_counts[syn_counts > threshold]
        if not attackers.empty:
            Security.syncflooding = True
            print("Possible SYN Flood Attack Detected from IP(s):")
            for ip in attackers.index:
                syncattack_ip=ip
                print(syncattack_ip)
                
        else:
            print("No SYN Flood Attack Detected.")

        if(Security.syncflooding and abnormaltraffic):
            print("Alert: Both SYN Flood and Abnormal Traffic Detected!")

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
