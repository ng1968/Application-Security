"""
You can auto-discover and run all tests with this command:

    $ pytest

Documentation:

* https://docs.pytest.org/en/latest/
* https://docs.pytest.org/en/latest/fixture.html
* http://flask.pocoo.org/docs/latest/testing/
"""

import pytest
from app import app
import models

from flask import Flask

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


def test_spell_check_page_no_access(client):
  # Checks if a 401 error code is received.
  # This should be the case since they do not have a cookie yet.
  res = client.get("/spell_check")
  assert res.status_code == 401
  assert b"Missing cookie" in res.data