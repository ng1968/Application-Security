from flask import Flask, escape, redirect, url_for

app = Flask(__name__)

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/login')
def login():
    return 'login'

@app.route('/register')
def register():
    return 'register'

@app.route('/spell_check')
def spell_check():
    return 'spell_check'
