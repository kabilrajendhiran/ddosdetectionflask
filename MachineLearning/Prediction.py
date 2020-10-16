import sys
from datetime import date
import math
import pyshark
import joblib
from flask import jsonify
from datetime import datetime
import mysql.connector

print("Live capturing")
cap = pyshark.LiveCapture(interface='\\Device\\NPF_{EBF0FD7C-33BB-4221-86B8-0ED5D258A54D}', display_filter='ip')
cap.set_debug()

srclist = []

dstlist = []
pktidlist = []
typelist = []
rst_flaglist = []
lengthlist = []
windowlist = []
seqlist = []
nxtseqlist = []
acklist = []
deltalist = []
protocollist =[]


def myfunction():


    try:
        def data_gathering(packet):
            c = 0
            global srclist
            global protocollist
            global dstlist
            global pktidlist
            global typelist
            global rst_flaglist
            global lengthlist
            global windowlist
            global seqlist
            global nxtseqlist
            global acklist
            global deltalist



            if ("TCP" == packet.highest_layer):
                #    print("TCP layer")
                src = packet["ip"].src  # 1 source

                dst = packet["ip"].dst  # 2 destination
                protocollist.append("1")
                pkt_id = int((packet["ip"].id), 16)  # 3 packet id
                type = packet["tcp"].flags_syn  # 4 syn
                reset_flag = packet["tcp"].flags_reset  # 5 reset
                length = packet["tcp"].len  # 6 length of packet
                window_size = packet["tcp"].window_size_value  # 7 window size
                sequence = packet["tcp"].seq  # 8 sequence number
                next_sequence = packet["tcp"].nxtseq  # 9 next sequence number
                acknowledgement = packet["tcp"].ack  # 10 acknowledgement number
                time_delta = packet["tcp"].time_delta

                srclist.append(src)
                dstlist.append(dst)
                pktidlist.append(pkt_id)
                typelist.append(type)
                rst_flaglist.append(reset_flag)
                lengthlist.append(length)
                windowlist.append(window_size)
                seqlist.append(sequence)
                nxtseqlist.append(next_sequence)
                acklist.append(acknowledgement)
                deltalist.append(time_delta)

            elif (packet.highest_layer == "UDP"):
                length = packet["udp"].length
                time_delta = packet["udp"].time_delta


                src = packet["ip"].src
                dst = packet["ip"].dst
                pkt_id = 0
                type = 99
                reset_flag = 99
                window_size = 0
                sequence = 99
                next_sequence = 99
                acknowledgement = 99
                srclist.append(src)
                dstlist.append(dst)
                protocollist.append("2")
                pktidlist.append(pkt_id)
                typelist.append(type)
                rst_flaglist.append(reset_flag)
                lengthlist.append(length)
                windowlist.append(window_size)
                seqlist.append(sequence)
                nxtseqlist.append(next_sequence)
                acklist.append(acknowledgement)
                deltalist.append(time_delta)

            elif (packet.highest_layer == "ICMP"):
                if ((packet["icmp"].type) != "3"):
                    src = packet["ip"].src
                    dst = packet["ip"].dst
                    delta_icmp = packet.frame_info.time_delta_displayed  # delta_time
                    time_delta = delta_icmp

                    # len_frame_icmp=packet.frame_info.cap_len  # window_size
                    seq_icmp = packet["icmp"].seq  # seq_number

                    len_icmp = packet["icmp"].data_len  # pkt_len

                    type_icmp = packet["icmp"].type  # flag
                    pkt_id = 99
                    type = type_icmp
                    sequence = seq_icmp
                    next_sequence = 99
                    acknowledgement = 99
                    reset_flag = 99
                    length = len_icmp
                    window_size = 0

                    srclist.append(src)
                    dstlist.append(dst)
                    protocollist.append("3")
                    pktidlist.append(pkt_id)
                    typelist.append(type)
                    rst_flaglist.append(reset_flag)
                    lengthlist.append(length)
                    windowlist.append(window_size)
                    seqlist.append(sequence)
                    nxtseqlist.append(next_sequence)
                    acklist.append(acknowledgement)
                    deltalist.append(time_delta)

       
        cap.apply_on_packets(data_gathering,packet_count=1000,timeout=60)

        features = list(zip(protocollist, pktidlist, typelist, rst_flaglist, lengthlist, windowlist, seqlist, nxtseqlist,acklist,deltalist))



        rf=joblib.load("static/RandomForest.pkl")

        result=rf.predict(features)
        print("0's")
        print(list(result).count(0))

        print("others")

        print(list(result).count(1))
        print(list(result).count(3))


        dos=list(result).count(1)+list(result).count(3)
        print(dos)

        normal=list(result).count(0)
        decision=""

        if(normal>dos):
            decision="We are safe"
        else:
            decision="DDoS Detected"







    except:
        print(sys.exc_info()[0])
        decision="We are safe"

    finally:
        currentdate = str(date.today())
        currenttime = str(datetime.time(datetime.now()))[0:8]
        currenttime = currenttime.replace(':','-')

        print(decision)
        print(currentdate)
        print(currenttime)




        insert_log="insert into logtable (predicted, date, time) values (%s,%s,%s)"
        values=(decision,currentdate,currenttime)

        print(insert_log)
        def databaseConnection():
            cnx = mysql.connector.connect(user='root', password='captainkabil',
                                          host='127.0.0.1',
                                          database='ddos')
            return cnx

        conn = databaseConnection()

        cursor = conn.cursor()
        cursor.execute(insert_log,values)
        conn.commit()
        conn.close()
        cap.clear()
        cap.close()
        return decision



