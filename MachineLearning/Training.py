from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import joblib
import numpy as np

import mysql.connector
class Train:

    def databaseConnection(self):
        cnx = mysql.connector.connect(user='root', password='captainkabil',
                                      host='127.0.0.1',
                                      database='ddos')
        return cnx


    def traindata(self):
        print("I'm Called")
        srclist = []
        dstlist = []
        protcollist = []
        pktidlist = []
        typelist = []
        rstflaglist = []
        pktlenlist = []
        windowsizelist = []
        seqlist = []
        nxtseqlist = []
        acklist = []
        deltalist = []
        labellist = []


        conn =self.databaseConnection()
        cursor=conn.cursor()
        getdata="select src,dst,protocol,pkt_id,types,rstflag,pkt_len,window_size,seq,next_seq,ack_no,delta,result from features;"
        cursor.execute(getdata)
        data=cursor.fetchall()

        for i in data:
            srclist.append(i[0])
            dstlist.append(i[1])
            protcollist.append(i[2])
            pktidlist.append(i[3])
            typelist.append(i[4])
            rstflaglist.append(i[5])
            pktlenlist.append(i[6])
            windowsizelist.append(i[7])
            seqlist.append(i[8])
            nxtseqlist.append(i[9])
            acklist.append(i[10])
            deltalist.append(i[11])
            labellist.append(i[12])


        cursor.close()
        conn.close()

        features = list(zip(protcollist, pktidlist, typelist, rstflaglist, pktlenlist, windowsizelist, seqlist, nxtseqlist,acklist,deltalist))
        #features = np.array(features).astype(np.float)
        X_train, X_test, y_train, y_test = train_test_split(features, labellist, test_size=0.1,random_state=10)  # 70% training and 30% test

        randomforest = RandomForestClassifier(n_estimators=10)
        randomforest.fit(X_train, y_train)

        joblib.dump(randomforest,"static/RandomForest.pkl")
        loaded_model = joblib.load("static/RandomForest.pkl")
        result = loaded_model.score(X_test, y_test)
        print(result)





#t=Train()
#t.traindata()


