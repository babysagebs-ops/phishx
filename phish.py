#importing required libraries

from flask import Flask, request, render_template,redirect, url_for, session
import numpy as np
import pandas as pd
from sklearn import metrics 
import warnings
import pickle
warnings.filterwarnings('ignore')
from feature import FeatureExtraction

file = open("pickle/model.pkl","rb")
gbc = pickle.load(file)
file.close()


app = Flask(__name__)
app.secret_key = "9f3a8c7d2e4b1a6f9c8d7e6a5b4c3d2f"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":

        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1,30) 

        y_pred =gbc.predict(x)[0]



        #1 is safe       
        #0 is unsafe
        probs = gbc.predict_proba(x)
        y_pro_phishing = probs[0,0]
        y_pro_non_phishing = probs[0,1]

        session['xx'] = round(y_pro_non_phishing, 2)
        session['url'] = url
        # if(y_pred ==1 ):
        pred = "It is {0:.2f}% safe to go".format(y_pro_non_phishing * 100)

        session['pred'] = pred

        return redirect(url_for('index'))
    return render_template("index.html",xx=session.pop('xx', -1),
        url=session.pop('url', ''))


if __name__ == "__main__":
    app.run(debug=True)