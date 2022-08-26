from crypt import methods
from flask import Flask ,render_template,flash,request ,session,url_for ,redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required
import FeatureExtraction
import pickle
import joblib
import numpy as np
#from sqlalchemy.testing.pickleable import User

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///phishdetect.sqlite3'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = "1234"



login_manager = LoginManager()
login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):
	return User.get(user_id)


db = SQLAlchemy(app)

class sites(db.Model):
		id = db.Column('s.n', db.Integer, primary_key=True)
		url = db.Column(db.String(100), nullable=False)


		def __init__(self, url):
			self.url= url



@app.route("/")
def index():

	return render_template("index.html",  sites=sites.query.all() )

@app.route("/phishing")
def phishing():
	return render_template("phishing.html")

@app.route("/about")
def about():
	return render_template("about.html")

@app.route("/login" , methods=['GET' ,'POST'])
def login(sites=None):

	if ('user' in session and  session ['user'] == ['sac123']):
		sites1= sites.query.all()
		return render_template("dashboard.html", sites=sites1)

	if request.method == 'POST':
		username=request.form.get('uname')
		userpassd=request.form.get('pass')
		print(username)

	if username == ["sac123"] and userpassd == ["sac123"]:
		session['user'] = username

		sites1= sites.query.all()
		return  render_template("dashboard.html", sites=sites1)

		return render_template("login.html")

@app.route("/dashboard")
@login_required
def dashboard():
		return render_template("dashboard.html", sites=sites.query.all())

# @app.route('/getURL',methods=['GET','POST'])
# def getURL():
#
#     if request.method == 'POST':
#         if not request.form['url']:
#             flash("please enter url" ,'error')
#         else:
#             url = sites(request.form.get('url'))
#             db.session.add(url)
#             db.session.commit()
#             return render_template('index.html')
#     return render_template('index.html')

@app.route('/getURL', methods=['GET','POST'])
def getURL():
	if request.method == 'POST':
		print(request.form['url'])
		url = sites(request.form['url'])
		data = FeatureExtraction.testData(request.form['url'])
		infile = open('RandomForestModel.sav','rb')
		model = pickle.load(infile)
		print(data)
		predicted_value = model.predict(data)
		print(predicted_value)

		if (predicted_value== -1):

			return render_template('index.html', sites=sites.query.all(), status='This website is Legitimate.')

		elif(predicted_value== 1):
			db.session.add(url)
			db.session.commit()

			return render_template('index.html', sites=sites.query.all(), status='This website is Phishing.')

		else:
			db.session.add(url)
			db.session.commit()

			return render_template('index.html', sites=sites.query.all(), status='This website is suspicious.')



@app.route('/api/check-url', methods=['GET', 'POST'])
def checkUrl():
	if True:
		print(request.form['url'])
		url = sites(request.form['url'])
		data = FeatureExtraction.testData(request.form['url'])
		infile = open('RandomForestModel.sav','rb')
		model = pickle.load(infile)
		print(data)
		predicted_value = model.predict(data)
		print(predicted_value)

		if (predicted_value== -1):

			return render_template('index.html', sites=sites.query.all(), status='This website is Legitimate.')

		elif(predicted_value== 1):
			db.session.add(url)
			db.session.commit()

			return {"status":'This website is Phishing.'}

		else:
			db.session.add(url)
			db.session.commit()

			return {"status": 'This website is suspicious.'}


if __name__ == '__main__':
#db.drop_all()
 db.create_all()
app.run(debug=True)