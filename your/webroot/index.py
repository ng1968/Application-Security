from flask import Flask, escape, redirect, render_template, request, session, url_for
import subprocess


DATABASE = 'database.txt'
app = Flask(__name__)

app.secret_key = b'd338cdce585dc7662749c2282b5b1d0938fd7c102a9ba14ad0bab6057a7cf9da5d53d9b690a5a43503e2f66c56894b6616ba2c4398e47e8b82cc6c10ee8ce372'

@app.route('/')
def index():
	# The root directory automatically redirects to login.
  return redirect(url_for('login'))

@app.route('/login', methods=['POST', 'GET'])
def login():
  error = None
  if request.method == 'POST':
    login_valid = validate_login(request.form['uname'], request.form['pword'], request.form['2fa'])
    if login_valid == 1:
      session['username'] = request.form['uname']
      return  render_template('login.html', login_output='success')
    elif login_valid == 2:
      return  render_template('login.html', login_output='incorrect')
    elif login_valid == 3:
      return  render_template('login.html', login_output='failure: two-factor wrong')
  # the code below is executed if the request method
  # was GET or the credentials were invalid
  return render_template('login.html', error=error)

def validate_login( uname, pword, twofa):
  # Checks if credential match.
  # 1 = Valid login.
  # 2 = incorrect username or password.
  # 3 = two-fa wrong.
  login_found = 0
  # Opens file
  with open(DATABASE, 'r') as read_descriptor:
    line_input = read_descriptor.readline()

    # Loop that reads file line by line.
    while line_input:
      line = line_input.split()
      # If they left the two-fa field empty
      if twofa == '':
        if( line[0] == uname and line[1] == pword and line[2] == 'empty' ):
          login_found = 1
          break
        elif( line[0] == uname and line[1] == pword and line[2] != 'empty' ):
          login_found = 3
          break
        elif( line[0] != uname or line[1] != pword ):
          login_found = 2
      else:
        if( line[0] == uname and line[1] == pword and line[2] == twofa ):
          login_found = 1
          break
        elif( line[0] == uname and line[1] == pword and line[2] != twofa ):
          login_found = 3
          break
        elif( line[0] != uname or line[1] != pword ):
          login_found = 2

      line_input = read_descriptor.readline()
  
  return login_found

@app.route('/register', methods=['POST', 'GET'])
def register():
  error = None
  if request.method == 'POST':
    # Checks if the username is already in the database.
    with open(DATABASE, 'r') as read_descriptor:
      if request.form['uname'] in read_descriptor.read():
        return render_template('register.html', register_output='Failure! Username already exists, try again')
      else:
        # Writes the registration information to the database.
        with open(DATABASE, 'a+') as write_descriptor:
          # If the 2FA if not entered we give it a default value.
          if request.form['2fa'] == '':
            registration_info = '{} {} {}\n'.format(request.form['uname'], request.form['pword'], 'empty')
          else:
            registration_info = '{} {} {}\n'.format(request.form['uname'], request.form['pword'], request.form['2fa'])
          write_descriptor.write(registration_info)
          return render_template('register.html', register_output='Account registered Success!')
  # the code below is executed if the request method
  # was GET or the credentials were invalid
  return render_template('register.html', error=error)

@app.route('/spell_check', methods=['POST', 'GET'])
def spell_check():
  error = None

  if request.method == 'POST':
    filename = 'input_file_%s.txt' % escape(session['username'])
    with open(filename, 'w+') as write_descriptor:
      write_descriptor.write(request.form['inputtext'])

    command = ['./spell_check', filename, 'wordlist.txt']
    output = subprocess.run(command, stdout=subprocess.PIPE)
    return render_template('spell_check.html', textout=request.form['inputtext'], misspelled=output.stdout.decode('utf-8'))

  return render_template('spell_check.html', error=error)


@app.route('/logout')
def logout():
  # remove the username from the session if it's there
  session.pop('username', None)
  return redirect(url_for('login'))

@app.errorhandler(404)
def page_not_found(error):
  return render_template('page_not_found.html'), 404