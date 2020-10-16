import mysql.connector

def databaseConnection():
    cnx = mysql.connector.connect(user='root', password='captainkabil',
                                  host='127.0.0.1',
                                  database='ddos')
    return cnx


def getdata():
    query="select * from logtable"
    conn=databaseConnection()
    cursor=conn.cursor()
    cursor.execute(query)
    data=cursor.fetchall()

    return data


