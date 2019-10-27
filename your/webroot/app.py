from flask import Flask, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, jwt_optional, create_access_token,
    jwt_refresh_token_required, create_refresh_token,
    get_jwt_identity, set_access_cookies,
    set_refresh_cookies, unset_jwt_cookies, get_raw_jwt
)
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

def add_to_logs(username_input, log_type_input, message_input, ip_input):
  new_user = models.LoggingModel(
    username = username_input,
    log_type = log_type_input,
    message = message_input,
    ip = ip_input,
    timestamp = str(time.time())
  )
  try:
    new_user.save_to_db()
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
      add_to_logs(request.form['uname'], 
        'login', 
        'incorrect: username not found', 
        request.remote_addr)
      return resp, 401
    
    if models.UserModel.verify_hash(request.form['pword'], current_user.password):
      if models.UserModel.verify_hash(request.form['2fa'], current_user.two_factor):
        access_token = create_access_token(identity = request.form['uname'])
        refresh_token = create_refresh_token(identity = request.form['uname'])
        resp = make_response(render_template('login.html', current_user=current_user.username, login_output='success'))
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        add_headers(resp)
        add_to_logs(request.form['uname'], 
          'login', 
          'success', 
          request.remote_addr)
        return  resp, 200
      else:
        resp = make_response(render_template('login.html', login_output='failure: two-factor wrong'))
        add_headers(resp)
        add_to_logs(request.form['uname'], 
          'login', 
          'failure: two-factor wrong', 
          request.remote_addr)
        return resp, 401
    else:
      resp = make_response(render_template('login.html', login_output='incorrect'))
      add_headers(resp)
      add_to_logs(request.form['uname'], 
        'login', 
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
    
    new_user = models.UserModel(
      username = request.form['uname'],
      password = models.UserModel.generate_hash(request.form['pword']),
      two_factor = models.UserModel.generate_hash(request.form['2fa'])
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

    resp = make_response(render_template('spell_check.html', textout=request.form['inputtext'], current_user=current_user, csrf_token=(get_raw_jwt() or {}).get("csrf"), misspelled=output.stdout.decode('utf-8')))
    add_headers(resp)
    return resp, 200

  current_user = get_jwt_identity()
  resp = make_response(render_template('spell_check.html', current_user=current_user, csrf_token=(get_raw_jwt() or {}).get("csrf")))
  add_headers(resp)
  return resp, 200


@app.route('/history', methods=['POST', 'GET'])
@jwt_required
def history():
  if request.method == 'POST':
    # current_user = get_jwt_identity()
    resp = make_response(render_template('history.html', textout=request.form['inputtext'], current_user=current_user, csrf_token=(get_raw_jwt() or {}).get("csrf"), misspelled=output.stdout.decode('utf-8')))
    # add_headers(resp)
    return resp, 200

  current_user = get_jwt_identity()
  query = models.SpellHistoryModel.find_results_by_username(current_user)
  resp = make_response(
    render_template('history.html', 
      current_user=current_user,
      numqueries=len(query),
      output = query,
      csrf_token=(get_raw_jwt() or {}).get("csrf")
      )
    )
  add_headers(resp)
  return resp, 200


@app.route('/token/refresh', methods=['POST', 'GET'])
@jwt_refresh_token_required
def token_refresh():
  current_user = get_jwt_identity()
  access_token = create_access_token(identity = current_user)
  resp = make_response(render_template('login.html', login_output='success'))
  set_access_cookies(resp, access_token)
  add_headers(resp)
  add_to_logs(current_user, 
    'token refresh', 
    'account refresh success', 
    request.remote_addr)
  return resp, 200


@app.route('/logout')
@jwt_required
def logout():
  # remove the username from the session if it's there
  try:
    resp = make_response(render_template('logout.html', login_output='success'))
    add_to_logs(get_jwt_identity(), 
      'logout', 
      'account log out success', 
      request.remote_addr)
    unset_jwt_cookies(resp)
    add_headers(resp)
    return resp, 200
  except:
    resp = make_response(render_template(login_output='Something went wrong'))
    add_headers(resp)
    add_to_logs(get_jwt_identity(), 
      'logout', 
      'something went wrong', 
      request.remote_addr)
    return resp, 500


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
