from flask import Flask
app = Flask(__name__)

@app.route('/')
def hello_world():
	return 'Hello wolrd'


if __name__ == "__main__":
	app.run(ssl_context=('/opt/infinitylxd-restful/ssl/cert.pem', '/opt/infinitylxd-restful/ssl/key.pem'),host='0.0.0.0')
