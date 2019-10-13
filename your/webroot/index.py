from flask import Flask, make_response, redirect, render_template, request, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_jwt_extended import (
    JWTManager, jwt_required, create_access_token,
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
app.config['JWT_ACCESS_COOKIE_PATH'] = '/spell_check'
app.config['JWT_REFRESH_COOKIE_PATH'] = '/token/refresh'
app.config['JWT_COOKIE_CSRF_PROTECT'] = True
app.config['JWT_CSRF_CHECK_FORM'] = True
app.config['JWT_COOKIE_SAMESITE'] = 'Lax'
app.config['JWT_SECRET_KEY'] = 'jwt-secret-string'
jwt = JWTManager(app)

import models

@app.route('/')
def index():
  # The root directory automatically redirects to login.
  return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
  if request.method == 'POST':
    current_user = models.UserModel.find_by_username(request.form['uname'])

    if not current_user:
      resp = make_response(render_template('login.html', login_output='incorrect'))
      resp.headers['Content-Security-Policy'] = "default-src 'self'"
      resp.headers['X-Content-Type-Options'] = 'nosniff'
      resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
      resp.headers['X-XSS-Protection'] = '1; mode=block'
      return resp, 401
    
    if models.UserModel.verify_hash(request.form['pword'], current_user.password):
      if models.UserModel.verify_hash(request.form['2fa'], current_user.two_factor):
        access_token = create_access_token(identity = request.form['uname'])
        refresh_token = create_refresh_token(identity = request.form['uname'])
        resp = make_response(render_template('login.html', login_output='success'))
        set_access_cookies(resp, access_token)
        set_refresh_cookies(resp, refresh_token)
        resp.headers['Content-Security-Policy'] = "default-src 'self'"
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        return  resp, 200
      else:
        resp = make_response(render_template('login.html', login_output='failure: two-factor wrong'))
        resp.headers['Content-Security-Policy'] = "default-src 'self'"
        resp.headers['X-Content-Type-Options'] = 'nosniff'
        resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
        resp.headers['X-XSS-Protection'] = '1; mode=block'
        return resp, 401
    else:
      resp = make_response(render_template('login.html', login_output='incorrect'))
      resp.headers['Content-Security-Policy'] = "default-src 'self'"
      resp.headers['X-Content-Type-Options'] = 'nosniff'
      resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
      resp.headers['X-XSS-Protection'] = '1; mode=block'
      return  resp, 401

  # was GET
  resp = make_response(render_template('login.html'))
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'
  return resp, 200

@app.route('/register', methods=['POST', 'GET'])
def register():
  if request.method == 'POST':
    # Checks if the username is already in the database.
    if models.UserModel.find_by_username(request.form['uname']):
      resp = make_response(render_template('register.html', register_output='Failure! Username already exists, try again'))
      resp.headers['Content-Security-Policy'] = "default-src 'self'"
      resp.headers['X-Content-Type-Options'] = 'nosniff'
      resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
      resp.headers['X-XSS-Protection'] = '1; mode=block'
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
      resp.headers['Content-Security-Policy'] = "default-src 'self'"
      resp.headers['X-Content-Type-Options'] = 'nosniff'
      resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
      resp.headers['X-XSS-Protection'] = '1; mode=block'
      return resp, 200
    except:
      resp = make_response(render_template('register.html', register_output='Something went wrong!'))
      resp.headers['Content-Security-Policy'] = "default-src 'self'"
      resp.headers['X-Content-Type-Options'] = 'nosniff'
      resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
      resp.headers['X-XSS-Protection'] = '1; mode=block'
      return resp, 500

  # was GET
  resp = make_response(render_template('register.html'))
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'
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
    resp = make_response(render_template('spell_check.html', textout=request.form['inputtext'], csrf_token=(get_raw_jwt() or {}).get("csrf"), misspelled=output.stdout.decode('utf-8')))
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp, 200

  resp = make_response(render_template('spell_check.html', csrf_token=(get_raw_jwt() or {}).get("csrf")))
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'
  return resp, 200


@app.route('/token/refresh', methods=['POST', 'GET'])
@jwt_refresh_token_required
def token_refresh():
  current_user = get_jwt_identity()
  access_token = create_access_token(identity = current_user)
  resp = make_response(render_template('login.html', login_output='success'))
  set_refresh_cookies(resp, refresh_token)
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'
  return resp, 200

@app.route('/logout')
def logout():
  # remove the username from the session if it's there
  try:
    resp = make_response(render_template('login.html', login_output='success'))
    unset_jwt_cookies(resp)
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return redirect(url_for('login')), 200
  except:
    resp = make_response(render_template(error='Something went wrong'))
    resp.headers['Content-Security-Policy'] = "default-src 'self'"
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
    resp.headers['X-XSS-Protection'] = '1; mode=block'
    return resp, 500

@app.errorhandler(404)
def page_not_found(error):
  resp = make_response(render_template('page_not_found.html'))
  resp.headers['Content-Security-Policy'] = "default-src 'self'"
  resp.headers['X-Content-Type-Options'] = 'nosniff'
  resp.headers['X-Frame-Options'] = 'SAMEORIGIN'
  resp.headers['X-XSS-Protection'] = '1; mode=block'
  return resp, 404
