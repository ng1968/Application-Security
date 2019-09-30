from flask import Flask, escape, redirect, render_template, request, session, url_for


DATABASE = 'database.txt'
app = Flask(__name__)

app.secret_key = b'd338cdce585dc7662749c2282b5b1d0938fd7c102a9ba14ad0bab6057a7cf9da5d53d9b690a5a43503e2f66c56894b6616ba2c4398e47e8b82cc6c10ee8ce372'

@app.route('/')
def index():
  if 'username' in session:
    return 'Logged in as %s' % escape(session['username'])
  return 'You are not logged in'

@app.route('/login', methods=['POST', 'GET'])
def login():
  error = None
  if request.method == 'POST':
    if validate_login( request.form['uname'], request.form['pword'], request.form['2fa'] ):
      session['username'] = request.form['uname']
      return 'success'
    else:
      return 'failure'
    

  # the code below is executed if the request method
  # was GET or the credentials were invalid
  return render_template('login.html', error=error)

def validate_login( uname, pword, twofa):
# Checks if the username is already in the database.
  login_found = False
  with open(DATABASE, 'r') as read_descriptor:
    line_input = read_descriptor.readline()

    while line_input:
      line = line_input.split()

      if twofa == '':
        if( line[0] == uname and line[1] == pword and line[2] == 'empty'):
          login_found = True

      if( line[0] == uname and line[1] == pword and line[2] == twofa ):
        login_found = True

      line_input = read_descriptor.readline()
  
  return login_found

@app.route('/register', methods=['POST', 'GET'])
def register():
  error = None
  if request.method == 'POST':
    # Checks if the username is already in the database.
    with open(DATABASE, 'r') as read_descriptor:
      if request.form['uname'] in read_descriptor.read():
        return '<p id="failure">Failure! Username already exists, try again<p>'
      else:
        # Writes the registration information to the database.
        with open(DATABASE, 'a+') as write_descriptor:
          # If the 2FA if not entered we give it a default value.
          if request.form['2fa'] == '':
            registration_info = '{} {} {}\n'.format(request.form['uname'], request.form['pword'], 'empty')
          else:
            registration_info = '{} {} {}\n'.format(request.form['uname'], request.form['pword'], request.form['2fa'])
          write_descriptor.write(registration_info)
          return '<p id="success">Account registered Success!<p>'
  # the code below is executed if the request method
  # was GET or the credentials were invalid
  return render_template('register.html', error=error)

@app.route('/spell_check')
def spell_check():
  return 'spell_check'

@app.route('/logout')
def logout():
  # remove the username from the session if it's there
  session.pop('username', None)
  return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
  return render_template('page_not_found.html'), 404