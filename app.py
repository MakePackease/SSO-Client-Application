# app.py

from flask import Flask, render_template, redirect, url_for, request, jsonify, session, g, make_response
import requests
from datetime import timedelta
from flask_jwt_extended import JWTManager, jwt_required, get_jwt_identity, verify_jwt_in_request
import jwt
from jwt import ExpiredSignatureError, InvalidTokenError, decode  # Import from jwt library directly
from flask_login import LoginManager, UserMixin, login_user, logout_user
import sqlite3
from flask_redis import FlaskRedis

# Initialize Flask application
app = Flask(__name__)
redis_client = FlaskRedis(app)

app.config['SECRET_KEY'] = 'awdwr245767i6thrgwryt23q87h3ry87ud3c8i4ftfohrvoyriotkiscekpr9845uect89je'  # Secret key for session management
app.secret_key = 'awdwr245767i6thrgwryt23q87h3ry87ud3c8i4ftfohrvoyriotkiscekpr9845uect89je'  # Replace with a secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['JWT_ALGORITHM'] = 'HS256'  # Ensure this matches Django's configuration
app.config['JWT_SECRET_KEY'] = 'django-insecure-6hj6o@b5#jz=+kmgr*2o!)271tq20*_9q3yjfzghd3a4^o($bv'
app.config['DEBUG'] = True
app.config['SESSION_COOKIE_NAME'] = "SINGLE_SESSION_COOKIE"
from flask_cors import CORS, cross_origin
# CORS(app)  # This will allow all domains to make requests
CORS(app, resources={r"/*": {"origins": ["http://127.0.0.1:8000", "http://127.0.0.1:5000" ]}})

jwt = JWTManager(app)

DATABASE = '/home/sahil/Documents/ParentApplication/ParentApp/db.sqlite3'
REDIS_URL = "redis://@localhost:6379/0"

def get_db():
    db = getattr(g, '_database', None)
    if db is None:
        db = g._database = sqlite3.connect(DATABASE)
    return db

@app.teardown_appcontext
def close_connection(exception):
    db = getattr(g, '_database', None)
    if db is not None:
        db.close()
# Define a basic route
current_user = None
@app.route('/')
@cross_origin(origins=["http://127.0.0.1:8000", "http://127.0.0.1:5050"])
def index():
    # auth_header = request.headers.get('Authorization')
    # print("Auth header: %s" % auth_header)
    # print(redis_client.get('current_user'))
    # print( session )
    # sso_session_id = request.cookies.get('sso-sessionid')
    # if not sso_session_id:
    #     print ('No sso-sessionid found', 401 ) # Unauthorized
    # else:
    #     print(sso_session_id)
    # cookie_value = request.cookies.get('my_cookie')
    # print( "cookie_value", cookie_value )
    # current_user = redis_client.get('current_user').decode('utf-8')
    # db = get_db()
    # cursor = db.execute('SELECT * FROM auth_user WHERE username = ?', (current_user,))
    # user = cursor.fetchone()
    # print (list(enumerate(user, 0)))

    # if user:
    return render_template('home.html')
    #     return jsonify(message=f"User found:  {user[4]}"),200
    # else:
    #     return jsonify(message="User not found"), 404
    # current_user = session.get('current_user')
    # const token = localStorage.getItem('jwtToken');
    # return render_template('index.html')
    print("-->",session.get('current_user'))
    if current_user:
        return jsonify(message=f'Hello, World!, {current_user}!')
    else:
        return jsonify(message='Hello, World!')  


def check_django_auth():
    url = 'http://127.0.0.1:8000/parent/get_logged_in_users/'  # Replace with actual URL
    # headers = {'Authorization': f'Bearer {token}'}  # Assuming token format

    try:
        response = requests.get(url)
        print("++>", response)
        if response.status_code == 200:
            return response.json()
        else:
            return None
    except requests.exceptions.RequestException as e:
        print("Request", response, "exception", e)
        return None


@app.route('/check_django_auth', methods=['GET'])
def handle_check_django_auth():
    if True:
        result = check_django_auth()
        if result:
            return jsonify(result), 200
        else:
            return jsonify({'error': 'Authentication failed'}), 401
    else:
        return jsonify({'error': 'Token not provided'}), 400

@app.route("/login", methods=["GET", "POST"])
def login():
    return redirect('http://127.0.0.1:8000/parent/logged_in_users_popup/')
    return render_template('login.html')
        
@app.route("/login2", methods=["GET", "POST"])
def login2():
    return render_template('login.html')
    return redirect('http://127.0.0.1:8000/parent/logged_in_users_popup/')
        


@app.before_request
def check_token():
    print ('Checking token', request )
    # if 'token' in request.args:
    auth_header = request.headers.get('Authorization')
    if auth_header:
        parts = auth_header.split()
        if len(parts) == 2 and parts[0].lower() == 'bearer':
            token = parts[1]
            print(f'Received token: {token}')
        # token = request.args.get('token')
            print('Received token: {token}')
            try:
                decoded_token = decode(token, app.config['JWT_SECRET_KEY'], algorithms=['HS256'])
                print(f'Decoded token: {decoded_token}')
                request.environ['jwt_identity'] = decoded_token['sub']
                session['current_user'] = decoded_token['sub']  # Store in session
                redis_client.set('current_user',  session['current_user'] )
                resp = make_response("Setting cookie!")
                resp.set_cookie('my_cookie', session['current_user'] , max_age=3600)  # Example: setting a cookie named 'my_cookie'

                # from datetime import datetime
                # now = datetime.now()
                # print(now)
                print(session.get('current_user'))
                current_user = session.get('current_user')
                # if request.url != url_for('protected'):  # Check if not requesting protected route
                #     return redirect(url_for('protected'))  # Redirect to protected route
                redirect(url_for('protected'))
            except ExpiredSignatureError:
                print('Token has expired')
                return jsonify({"msg": "Token has expired !"}), 401
            except InvalidTokenError:
                print('Invalid token')
                return jsonify({"msg": "Invalid token"}), 401
        else:
            print('Invalid Authorization header format')
            return jsonify({"msg": "Invalid Authorization header format"}), 401
    else:
        print('Log in required')

@app.route('/protected', methods=['GET'])
@cross_origin(origins=["http://127.0.0.1:8000", "http://127.0.0.1:5000"])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    print("Current", current_user)
    return jsonify(logged_in_as=current_user), 200

@app.route('/logout', methods=['GET'])
def logout():
    return "logout"
if __name__ == '__main__':
    app.run(debug=True)

