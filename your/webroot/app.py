from flask import Flask, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_optional, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, get_raw_jwt
)
from secrets import token_hex
import subprocess
import time


app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'some-secret-string'

db = SQLAlchemy(app)
@app.before_first_request
def create_tables():
  db.create_all()

app.config['JWT_TOKEN_LOCATION'] = ['cookies']
app.config['JWT_ACCESS_COOKIE_PATH'] = ['/login', '/register', '/spell_check', '/history', '/logout']
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

import models

def add_headers(resp):
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'


def add_login_to_db(username_input, message_input, ip_input):
  current_user = models.UserModel.find_by_username(request.form['uname'])
  
  if not current_user:
    current_id = -1
  else:
    current_id = models.UserModel.id_from_username(username_input)[0]
  login = models.LoggingModel(
    user_id=current_id,
    username = username_input,
    log_type = 'login',
    message = message_input,
    ip = ip_input,
    timestamp = str(time.time())
  )

  try:    
    login.save_to_db() 
    if message_input == 'success':
      logout = models.LoggingModel(
        user_id=current_id,
        username = username_input,
        log_type = 'logout',
        message = 'Not Logged Out Yet.',
        ip = ip_input,
        timestamp = 'N/A.'
      )
      logout.save_to_db()
    return 200
  except:
    resp = make_response(render_template('login.html', login_output='something went wrong'))
    return resp, 500


@app.route('/')
def index():
  # The root directory automatically redirects to login.
  return redirect(url_for('login'))


@app.route('/login', methods=['POST', 'GET'])
@jwt_optional
def login():
  if request.method == 'POST':
    current_user = models.UserModel.find_by_username(request.form['uname'])

    if not current_user:
      resp = make_response(render_template('login.html', login_output='incorrect'))
      add_headers(resp)
      add_login_to_db(request.form['uname'], 
        'incorrect: username not found', 
        request.remote_addr)
      return resp, 401
    
    if models.UserModel.verify_hash(request.form['pword'], current_user.password, current_user.pepper):
      if models.UserModel.verify_hash(request.form['2fa'], current_user.two_factor, current_user.pepper):
        access_token = create_access_token(identity = request.form['uname'])
        refresh_token = create_refresh_token(identity = request.form['uname'])
        resp = make_response(render_template('login.html', current_user=current_user.username, login_output='success'))
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        add_headers(resp)
        add_login_to_db(request.form['uname'], 
          'success', 
          request.remote_addr)
        return  resp, 200
      else:
        resp = make_response(render_template('login.html', login_output='failure: two-factor wrong'))
        add_headers(resp)
        add_login_to_db(request.form['uname'], 
          'failure: two-factor wrong', 
          request.remote_addr)
        return resp, 401
    else:
      resp = make_response(render_template('login.html', login_output='incorrect'))
      add_headers(resp)
      add_login_to_db(request.form['uname'], 
        'incorrect: wrong password', 
        request.remote_addr)
      return  resp, 401

  # was GET
  current_user = get_jwt_identity()
  resp = make_response(render_template('login.html', current_user=current_user))
  add_headers(resp)
  return resp, 200


@app.route('/register', methods=['POST', 'GET'])
@jwt_optional
def register():
  if request.method == 'POST':
    # Checks if the username is already in the database.
    if models.UserModel.find_by_username(request.form['uname']):
      resp = make_response(render_template('register.html', register_output='Failure! Username already exists, try again'))
      add_headers(resp)
      return resp, 401
    
    salt = token_hex(nbytes=16)
    new_user = models.UserModel(
      username = request.form['uname'],
      password = models.UserModel.generate_hash(request.form['pword'], salt),
      two_factor = models.UserModel.generate_hash(request.form['2fa'], salt),
      pepper = salt
    )
    
    try:
      new_user.save_to_db()
      access_token = create_access_token(identity = request.form['uname'])
      refresh_token = create_refresh_token(identity = request.form['uname'])
      resp = make_response(render_template('register.html', register_output='Account registered Success!'))
      add_headers(resp)
      return resp, 200
    except:
      resp = make_response(render_template('register.html', register_output='Something went wrong!'))
      add_headers(resp)
      return resp, 500

  # was GET
  current_user = get_jwt_identity()
  resp = make_response(render_template('register.html', current_user=current_user))
  add_headers(resp)
  return resp, 200


@app.route('/spell_check', methods=['POST', 'GET'])
@jwt_required
def spell_check():
  if request.method == 'POST':
    filename = 'input_file_%s.txt' % str(time.time())
    with open(filename, 'w+') as write_descriptor:
      write_descriptor.write(request.form['inputtext'])

    command = ['./spell_check', filename, 'wordlist.txt']
    output = subprocess.run(command, stdout=subprocess.PIPE)
    subprocess.run(['rm', filename], stdout=subprocess.PIPE)
    current_user = get_jwt_identity()
    # Adding query to history
    new_query = models.SpellHistoryModel(
      user_id=models.UserModel.id_from_username(current_user)[0],
      username = current_user,
      querytext = request.form['inputtext'],
      queryresults = output.stdout.decode('utf-8')
    )
    try:
      new_query.save_to_db()
    except:
      resp = make_response(render_template('spell_check.html', textout='Something went wrong!'))
      add_headers(resp)
      return resp, 500

    resp = make_response(render_template('spell_check.html', 
      textout=request.form['inputtext'], 
      current_user=current_user, 
      csrf_token=(get_raw_jwt() or {}).get("csrf"), 
      misspelled=output.stdout.decode('utf-8')))
    add_headers(resp)
    return resp, 200

  current_user = get_jwt_identity()
  resp = make_response(render_template('spell_check.html', current_user=current_user, csrf_token=(get_raw_jwt() or {}).get("csrf")))
  add_headers(resp)
  return resp, 200


@app.route('/history', methods=['POST', 'GET'])
@jwt_required
def history():
  current_user = get_jwt_identity()
  if request.method == 'POST':
    query = models.SpellHistoryModel.find_results_by_username(request.form['userquery'])
    resp = make_response(
      render_template('history.html', 
        current_user=current_user,
        admin_user=True,
        numqueries=len(query),
        query_output = query,
        csrf_token=(get_raw_jwt() or {}).get("csrf")
        )
      )
    add_headers(resp)
    return resp, 200

  query = models.SpellHistoryModel.find_results_by_username(current_user)
  if current_user == 'admin':
    resp = make_response(
      render_template('history.html', 
        current_user=current_user,
        admin_user=True,
        numqueries=len(query),
        query_output = query,
        csrf_token=(get_raw_jwt() or {}).get("csrf")
        )
      )
  else:
    resp = make_response(
      render_template('history.html', 
      current_user=current_user,
      numqueries=len(query),
      query_output = query,
      csrf_token=(get_raw_jwt() or {}).get("csrf")
      )
    )

  add_headers(resp)
  return resp, 200


@app.route('/history/query<queryid>', methods=['POST', 'GET'])
@jwt_required
def history_queryid(queryid):
  current_user = get_jwt_identity()
  try:
    query = models.SpellHistoryModel.find_results_by_queryid(int(queryid))
    if current_user == query[1] or current_user == 'admin':
      resp = make_response(
          render_template('query.html', 
          current_user=current_user,
          query_output = query,
          csrf_token=(get_raw_jwt() or {}).get("csrf")
          )
        )
      add_headers(resp)
      return resp, 200
    else:
      resp = make_response(
          render_template('query.html', 
          current_user=current_user,
          error='You do not have access to this query.',
          csrf_token=(get_raw_jwt() or {}).get("csrf")
          )
        )
      add_headers(resp)
      return resp, 401
  except:
    resp = make_response(
        render_template('query.html', 
        current_user=current_user,
        error='Your Query does not exists.',
        csrf_token=(get_raw_jwt() or {}).get("csrf")
        )
      )
    add_headers(resp)
    return 404

@app.route('/token/refresh', methods=['POST', 'GET'])
@jwt_refresh_token_required
def token_refresh():
  current_user = get_jwt_identity()
  access_token = create_access_token(identity = current_user)
  resp = make_response(render_template('login.html', login_output='success'))
  set_access_cookies(resp, access_token)
  add_headers(resp)
  add_login_to_db(current_user, 
    'account refresh success', 
    request.remote_addr)
  return resp, 200


@app.route('/logout', methods=['GET'])
@jwt_required
def logout():
  current_user = get_jwt_identity()
  # remove the username from the session if it's there
  try:
    resp = make_response(render_template('logout.html', login_output='success'))
    # Update logout
    models.LoggingModel.update_logout(current_user, 'success', str(time.time()))
    unset_jwt_cookies(resp)
    add_headers(resp)
    return resp, 200
  except:
    resp = make_response(render_template('logout.html', login_output='Something went wrong'))
    add_headers(resp)
    # Update logout
    models.LoggingModel.update_logout(current_user, 'Something Went Wrong', str(time.time()))
    return resp, 500


@app.route('/login_history', methods=['POST', 'GET'])
@jwt_required
def login_history():
  users = models.UserModel.id_username()
  current_user = get_jwt_identity()
  # POST
  if request.method == 'POST':
    if current_user == 'admin':
      userid = request.form['userid']
      query = models.LoggingModel.find_results_by_user_id(userid)
      resp = make_response(
        render_template('login_history.html', 
          current_user=current_user,
          output=users,
          logging_output=query,
          csrf_token=(get_raw_jwt() or {}).get("csrf")
          )
        )
      add_headers(resp)
      return resp, 200
    else:
      resp = make_response(
        render_template('login_history.html', 
          current_user=current_user,
          error='Sorry you do not have access',
          csrf_token=(get_raw_jwt() or {}).get("csrf")
          )
        )
      add_headers(resp)
      return resp, 401

  # GET
  if current_user == 'admin':
    resp = make_response(
      render_template('login_history.html', 
        current_user=current_user,
        output=users,
        csrf_token=(get_raw_jwt() or {}).get("csrf")
        )
      )
    add_headers(resp)
    return resp, 200
  else:
    resp = make_response(
      render_template('login_history.html', 
        current_user=current_user,
        error='Sorry you do not have access',
        csrf_token=(get_raw_jwt() or {}).get("csrf")
        )
      )
    add_headers(resp)
    return resp, 401



@app.errorhandler(404)
@jwt_optional
def page_not_found(error):
  current_user = get_jwt_identity()
  if current_user:
    resp = make_response(render_template('page_not_found.html', current_user=current_user))
    add_headers(resp)
  else:
    resp = make_response(render_template('page_not_found.html'))
    add_headers(resp)
  return resp, 404
