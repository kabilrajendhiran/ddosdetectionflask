import sys

import mysql.connector
from flask import request,jsonify


def databaseConnection():
    cnx = mysql.connector.connect(user='root', password='captainkabil',
                                  host='127.0.0.1',
                                  database='ddos')
    return cnx

def registeration(data):

    try:
        username = data['username']
        email = data['email']
        password = data['password']
        mobile=data['mobile']
        print(mobile)


        insertreg="insert into user (name, password, emailid, mobileno)values (%s,%s,%s,%s)"
        values=(username,password,email,mobile)
        conn=databaseConnection()
        cursor=conn.cursor()
        cursor.execute(insertreg,values)
        conn.commit()
        conn.close()

        return jsonify({"res": "0"})
    except mysql.connector.IntegrityError:
        print(sys.exc_info())
        return jsonify({"res":"1"})

    except :
        return jsonify({"res": "2"})

def login(data):
    try:
        username = data['username']
        password = data['password']

        print(username)
        print(password)
        query="select count(*) as count from user where name='"+username+"' and password='"+password+"'"
        conn=databaseConnection()
        cursor=conn.cursor()
        cursor.execute(query)
        rowcount=cursor.fetchall()

        for i in rowcount:
            a=i[0]

        conn.commit()
        conn.close()


        if(a==1):
            return jsonify({"res":"0"})
        else:
            return jsonify({"res":"1"})

    except :
         print(sys.exc_info())
         return jsonify({"res": "1"})
