import pyshark
import datetime
capture = pyshark.LiveCapture(interface='en1')
# Define lists to store IP header fields
class Statistics():
    @staticmethod
    def Logs(req_port,src_ip,dst_ip,pkt_time):
        today = datetime.date.today()
        with open('log.csv','a')as f:
            f.write(f"Date: {today}"+","+f"Time: {pkt_time}"+","+f"Source IP: {src_ip}"+","+
                    f"Destination IP: {dst_ip}"+","+
                    f"Requested Port: {req_port}"+","+"\n")
        print("Logging...")

class Security():
    syncflooding=False

    @staticmethod
    def SyncFlooding():
        print ("Detecting SYN Flooding Attack...")
    @staticmethod
    def MeasureBandwidth():
        print ("Measuring Bandwidth...")

class Info:
    @staticmethod
    def packetdetector():
        ipversion=[]
        ipheaders_length=[]
        iptos=[]
        ipipidentification=[]
        ipflags=[]
        ipfragment_offset=[]
        ipttl=[]
        ipprotocol=[]
        ipheader_checksum=[]
        ipsource_address=[]
        ipdestination_address=[]
        # เก็บ TCP fields
        tcp_srcport = []
        tcp_dstport = []
        tcp_seq = []
        tcp_ack = []
        tcp_len = []
        tcp_window = []
        tcp_flags = []
        tcp_flag_syn = []
        tcp_flag_ack = []
        tcp_flag_fin = []
        tcp_flag_rst = []
        try:
            for packet in capture.sniff_continuously():
                try:
                    if 'TCP' in packet:
                        protocol = packet.transport_layer
                        source_address = packet.ip.src
                        source_port = packet.tcp.srcport
                        destination_address = packet.ip.dst
                        destination_port = packet.tcp.dstport 
                        packet_time = packet.sniff_time
                        packet_timestamp = packet.sniff_timestamp

                        # เก็บค่า TCP
                        tcp_srcport.append(source_port)
                        tcp_dstport.append(destination_port)
                        tcp_seq.append(packet.tcp.seq)
                        tcp_ack.append(packet.tcp.ack)
                        tcp_len.append(packet.tcp.len)
                        tcp_window.append(packet.tcp.window_size)
                        tcp_flags.append(packet.tcp.flags)
                        tcp_flag_syn.append(packet.tcp.flags_syn)
                        tcp_flag_ack.append(packet.tcp.flags_ack)
                        tcp_flag_fin.append(packet.tcp.flags_fin)
                        tcp_flag_rst.append(packet.tcp.flags_reset)

                        # print(f"[TCP] {source_address}:{source_port} -> {destination_address}:{destination_port}, "
                        #       f"SEQ={packet.tcp.seq}, ACK={packet.tcp.ack}, LEN={packet.tcp.len}, "
                        #       f"Flags(SYN={packet.tcp.flags_syn}, ACK={packet.tcp.flags_ack}, FIN={packet.tcp.flags_fin}, RST={packet.tcp.flags_reset}), "
                        #       f"Time={packet_time}")
                    elif 'UDP' in packet:
                        pass

                    if 'IP' in packet:
                        ipversion.append(packet.ip.version)
                        ipheaders_length.append(packet.ip.hdr_len)
                        iptos.append(packet.ip.dsfield)
                        ipipidentification.append(packet.ip.id)
                        ipflags.append(packet.ip.flags)
                        ipfragment_offset.append(packet.ip.frag_offset)
                        ipttl.append(packet.ip.ttl)
                        ipprotocol.append(packet.ip.proto)
                        ipheader_checksum.append(packet.ip.checksum)
                        ipsource_address.append(packet.ip.src)
                        ipdestination_address.append(packet.ip.dst)

                        Statistics.Logs(destination_port,source_address,destination_address,packet_time)
                except AttributeError:
                    pass
        except (KeyboardInterrupt, EOFError):
            print("\nStopped packet capturing safely.")

Info.packetdetector()
