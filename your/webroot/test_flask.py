import pytest
from app import app
import models
import re

from flask import Flask, make_response, render_template
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_raw_jwt

@pytest.fixture
def client():
  return app.test_client()


def test_index(client):
  # tests if the site redirects.
  res = client.get("/")
  assert res.status_code == 302


def test_login_page(client):
  # Tests if login page loads properly.
  res = client.get("/login")
  assert res.status_code == 200
  assert b"Log In - Flaskr" in res.data


def test_register_page(client):
  # Tests if register page loads properly.
  res = client.get("/register")
  assert res.status_code == 200
  assert b"Register - Flaskr" in res.data


def test_register_entry_success(client):
  # Tests if register page loads properly.
  sent = {"uname" : "test1",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/register", data=sent)
  models.UserModel.delete_user("test1")
  assert res.status_code == 200
  assert b"<p id=\"success\">Account registered Success!<p>" in res.data


def test_register_entry_already_exists(client):
  # Tests if register page loads properly.
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/register", data=sent)
  assert res.status_code == 401
  assert b"<p id=\"success\">Failure! Username already exists, try again<p>" in res.data


def test_login_valid(client):
  # Tests if register page loads properly.
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)
  assert res.status_code == 200
  assert b"<p id=\"result\">success</p>" in res.data


def test_login_invalid(client):
  # Tests if register page loads properly.
  sent = {"uname" : "test",
          "pword" : "test1",
          "2fa" : "test"}
  res = client.post("/login", data=sent)
  assert res.status_code == 401
  assert b"<p id=\"result\">incorrect</p>" in res.data


def test_login_invalid_2fa(client):
  # Tests if register page loads properly.
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test1"}
  res = client.post("/login", data=sent)
  assert res.status_code == 401
  assert b"<p id=\"result\">failure: two-factor wrong</p>" in res.data


def test_spell_check_page_no_access(client):
  # Checks if a 401 error code is received.
  # This should be the case since they do not have a cookie yet.
  res = client.get("/spell_check")
  assert res.status_code == 401
  assert b"Missing cookie" in res.data


def test_spell_check_page_access(client):
  # Checks if a 401 error code is received.
  # This should be the case since they do not have a cookie yet.
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)
  res = client.get("/spell_check")
  assert res.status_code == 200
  assert b"Spell Check - Flaskr" in res.data


def test_spell_check_page_double_submit(client):
  # Checks if a 401 error code is received.
  # This should be the case since they do not have a cookie yet.
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)

  res = client.get("/spell_check")
  cookie = re.findall(r"(([a-z0-9]+)-([a-zA-Z0-9]+)-([a-zA-Z0-9]+)-([a-zA-Z0-9]+)-([a-z0-9]+))\w", res.data.decode("utf-8"))[0][0]
  sent_to_post = {"inputtext" : "test",
                  "csrf_token" : cookie}

  res1 = client.post("/spell_check", data=sent_to_post)
  
  assert res1.status_code == 401
  assert b"CSRF double submit tokens do not match" in res1.data


def test_logout(client):
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)
  res1 = client.get("/logout")
  assert res1.status_code == 200
  assert b"success" in res1.data


def test_404(client):
  res = client.post("/rqegdfsgaffsbavsf")

  assert res.status_code == 404
  assert b"Why are you here??" in res.data


def test_history_admin_access(client):
  sent = {"uname" : "admin",
          "pword" : "administrator",
          "2fa" : "12345678901"}
  res = client.post("/login", data=sent)

  res = client.get("/history")
  
  assert res.status_code == 200
  assert b"userquery" in res.data


def test_history_query_1(client):
  sent = {"uname" : "admin",
          "pword" : "administrator",
          "2fa" : "12345678901"}
  res = client.post("/login", data=sent)

  res1 = client.get("/history/query1")
  
  assert res.status_code == 200
  assert b"""<td id="queryid">1</td>
    <td id="username">test</td>
    <td id="querytext">test</td>
    <td id="queryresults"></td>""" in res1.data


def test_history_query_invalid_user(client):
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)

  res1 = client.get("/history/query4")
  
  assert res1.status_code == 401
  assert b"You do not have access to this query." in res1.data


def test_login_history_access(client):
  sent = {"uname" : "admin",
          "pword" : "administrator",
          "2fa" : "12345678901"}
  res = client.post("/login", data=sent)

  res1 = client.get("/login_history")

  assert res1.status_code == 200
  assert b"admin" in res1.data


def test_login_history_invalid_access(client):
  sent = {"uname" : "test",
          "pword" : "test",
          "2fa" : "test"}
  res = client.post("/login", data=sent)

  res1 = client.get("/login_history")

  assert res1.status_code == 401
  assert b"Sorry you do not have access" in res1.data