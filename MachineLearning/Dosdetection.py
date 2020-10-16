import pyshark
import mysql.connector
class Dosdetection:


      def __init__(self):
          self.c=0
          self.srclist = []
          self.list = []
          self.dstlist = []
          self.pktidlist = []
          self.typelist = []
          self.rst_flaglist = []
          self.lengthlist = []
          self.windowlist = []
          self.seqlist = []
          self.nxtseqlist = []
          self.acklist = []
          self.deltalist = []

          self.udp_len = []
          self.udp_timedelta = []

          self.icmp_deltalist=[]
          self.icmp_frame_lenlist=[]
          self.icmp_seqlist=[]
          self.conn = self.databaseConnection()


      def data_gathering(self,cap,tcp=0,udp=0,icmp=0):





        for packet in cap:
          if ("TCP" == packet.highest_layer):
              #    print("TCP layer")
              src = packet["ip"].src  # 1 source
              dst = packet["ip"].dst  # 2 destination
              pkt_id = int((packet["ip"].id), 16)  # 3 packet id
              type = packet["tcp"].flags_syn  # 4 syn
              reset_flag = packet["tcp"].flags_reset  # 5 reset
              length = packet["tcp"].len  # 6 length of packet
              window_size = packet["tcp"].window_size_value  # 7 window size
              sequence = packet["tcp"].seq  # 8 sequence number
              next_sequence = packet["tcp"].nxtseq  # 9 next sequence number
              acknowledgement = packet["tcp"].ack  # 10 acknowledgement number
              time_delta=packet["tcp"].time_delta
              cursor = self.conn.cursor()
              print("source : "+str(src)+" destination : "+str(dst)+" packet_id : "+str(pkt_id)+" type : "+str(type)+" reset_flag : "+str(reset_flag)+" length : "+str(length)+" window size : "+str(window_size)+" sequence no. : "+str(sequence)+ " next sequence no. :"+str(next_sequence)+" acknowledgement : "+str(acknowledgement)+" time_delta : "+str(time_delta))
              insertquery = "insert into features(protocol,pkt_id,types,rstflag,pkt_len,window_size,seq,next_seq,ack_no,delta,result) values (" + str(1) + "," + str(pkt_id) + "," + str(type) + "," + str(reset_flag) + "," + str(length) + "," + str(window_size) + "," + str(sequence) + "," + str(next_sequence) + "," + str(acknowledgement) + "," + str(time_delta) + "," + str(tcp) + ");"
              cursor.execute(insertquery)
              self.c=self.c+1
              print(self.c)
              cursor.close()

              result_tcp=tcp

              #self.databaseinsert(src,dst,"1",pkt_id,type,reset_flag,length,window_size,sequence,next_sequence,acknowledgement,time_delta,result_tcp)
          elif(packet.highest_layer=="UDP"):
              self.lengthlist.append(packet["udp"].length)
              self.deltalist.append(packet["udp"].time_delta)
              length=packet["udp"].length
              time_delta=packet["udp"].time_delta
              src=packet["ip"].src
              dst=packet["ip"].dst
              pkt_id=0
              type=99
              reset_flag=99
              window_size=0
              sequence=99
              next_sequence=99
              acknowledgement=99
              cursor=self.conn.cursor()
              insertquery = "insert into features(protocol,pkt_id,types,rstflag,pkt_len,window_size,seq,next_seq,ack_no,delta,result) values (" + str(2) + "," + str(pkt_id) + "," + str(type) + "," + str(reset_flag) + "," + str(length) + "," + str(window_size) + "," + str(sequence) + "," + str(next_sequence) + "," + str(acknowledgement) + "," + str(time_delta) + "," + str(udp) + ");"
              cursor.execute(insertquery)
              cursor.close()
              self.c = self.c + 1
              print(self.c)

          elif(packet.highest_layer=="ICMP"):
              if((packet["icmp"].type)!="3"):
                 src=packet["ip"].src
                 dst=packet["ip"].dst
                 delta_icmp=packet.frame_info.time_delta_displayed  # delta_time
                 time_delta=delta_icmp

                # len_frame_icmp=packet.frame_info.cap_len  # window_size
                 seq_icmp=packet["icmp"].seq  # seq_number

                 len_icmp=packet["icmp"].data_len  # pkt_len

                 type_icmp=packet["icmp"].type  # flag
                 pkt_id=99
                 type=type_icmp
                 result_icmp=icmp
                 sequence=seq_icmp
                 next_sequence=99
                 acknowledgement=99
                 reset_flag=99
                 length=len_icmp
                 window_size=0
                 cursor = self.conn.cursor()
                 insertquery = "insert into features(protocol,pkt_id,types,rstflag,pkt_len,window_size,seq,next_seq,ack_no,delta,result) values (" + str(3) + "," + str(pkt_id) + "," + str(type) + "," + str(reset_flag) + "," + str(length) + "," + str(window_size) + "," + str(sequence) + "," + str(next_sequence) + "," + str(acknowledgement) + "," + str(time_delta) + "," + str(icmp) + ");"
                 cursor.execute(insertquery)
                 cursor.close()
                 self.c = self.c + 1
                 print(self.c)


      def databaseinsert(self,src,dst,protocol,pkt_id,type,reset,length,window,seq,next_seq,ack,delta,result):
          conn=self.databaseConnection()
          cursor = conn.cursor()


          insertquery="insert into features(protocol,pkt_id,types,rstflag,pkt_len,window_size,seq,next_seq,ack_no,delta,result) values ("+str(protocol)+","+str(pkt_id)+","+str(type)+","+str(reset)+","+str(length)+","+str(window)+","+str(seq)+","+str(next_seq)+","+str(ack)+","+str(delta)+","+str(result)+");"

          cursor.execute(insertquery)
          cursor.close()



      def databaseConnection(self):
          cnx = mysql.connector.connect(user='root', password='captainkabil',
                                        host='127.0.0.1',
                                        database='ddos')
          return cnx

data=Dosdetection()
#
#
#
cap1=pyshark.FileCapture("static/normal.cap",keep_packets=True,display_filter='ip')
data.data_gathering(cap1)
cap1.close()
#
#
cap2=pyshark.FileCapture("static/dos.cap",keep_packets=True,display_filter='ip')
data.data_gathering(cap2,1,2,3)
cap2.close()
data.conn.commit()
data.conn.close()






#data.databaseinsert(src,dst,pkt_id,type,reset_flag,length,window_size,sequence,next_sequence,acknowledgement,time_delta,res)






# cap4=pyshark.FileCapture("../data/udpnormal.cap",keep_packets=True,display_filter='ip')
# cap4.apply_on_packets(data.data_gathering_udp)
# cap4.close()
#
# cap5=pyshark.FileCapture("../data/icmpflood.cap",keep_packets=True,display_filter='ip')
# cap5.apply_on_packets(data.data_gathering_icmp)
# cap5.close()
#
# cap6=pyshark.FileCapture("../data/icmpnormal.cap",keep_packets=True,display_filter='ip')
# cap6.apply_on_packets(data.data_gathering_icmp)
# cap6.close()




