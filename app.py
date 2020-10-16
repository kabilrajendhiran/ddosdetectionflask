from MachineLearning import Prediction
from user import usercontroller
from flask import Flask ,jsonify,request
from flask_cors import CORS
import sys
import os
from MachineLearning import logdata


app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = "static"

cors=CORS(app)


@app.route('/')
def hello_world():
    data=jsonify('Hello World')
    return data


@app.route('/prediction')
def predict():
    print("IM WORKING")

    data=jsonify({"res":Prediction.myfunction()})
    return data

@app.route('/train')
def train():
    try:
        from MachineLearning import Training
        t = Training.Train()
        t.traindata()
        data="Success"
        return jsonify(data)
    except:
        data="OOPs Something went wrong"
        print(sys.exc_info()[0])
        return jsonify(data)

@app.route("/uploadmodel", methods=['POST'])
def upload_file():
    try:
        file=request.files["file"]
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], "RandomForest.pkl"))
        res=jsonify({"res":"Successfully uploaded"})
        return res
    except:
        print(sys.exc_info()[0])
        return jsonify({"res":"Failed"})

@app.route("/uploadnormal", methods=['POST'])
def upload_file_normalfile():
    try:
        file=request.files["file"]
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], "normal.cap"))
        res=jsonify({"res":"Successfully uploaded"})
        return res
    except:
        print(sys.exc_info()[0])
        return jsonify({"res":"Failed"})

@app.route("/uploaddos", methods=['POST'])
def upload_file_dosfile():
    try:
        file=request.files["file"]
        file.save(os.path.join(app.config['UPLOAD_FOLDER'], "dos.cap"))
        res=jsonify({"res":"Successfully uploaded"})
        return res
    except:

        return jsonify({"res":"Failed"})

@app.route("/training")
def insertintodatabase():
    try:
        from MachineLearning import Dosdetection
        train()
    except:
        print(sys.exc_info()[0])

@app.route("/reg",methods=['GET','POST'])
def register():
    data = request.get_json()
    res=usercontroller.registeration(data)

    return res

@app.route("/login",methods=['GET','POST'])
def login():
    data=request.get_json();
    res=usercontroller.login(data)
    return res

@app.route("/log")
def getLog():
    return jsonify(logdata.getdata())



if __name__ == '__main__':
    app.run()
