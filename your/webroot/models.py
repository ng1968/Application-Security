from app import db
from passlib.hash import pbkdf2_sha256 as sha256

class UserModel(db.Model):
  __tablename__ = 'users'

  id = db.Column(db.Integer, primary_key = True)
  username = db.Column(db.String(120), unique = True, nullable = False)
  password = db.Column(db.String(120), nullable = False)
  two_factor = db.Column(db.String(120), nullable = False)
  
  def save_to_db(self):
    db.session.add(self)
    db.session.commit()
  
  @classmethod
  def find_by_username(cls, username):
    return cls.query.filter_by(username = username).first()

  @classmethod
  def delete_user(cls, username):
    db.session.delete(cls.query.filter_by(username = username).first())
    db.session.commit()

  @staticmethod
  def generate_hash(password):
    return sha256.hash(password)
  
  @staticmethod
  def verify_hash(password, hash):
    return sha256.verify(password, hash)

class SpellHistoryModel(db.Model):
  __tablename__ = 'spellcheckhistory'

  queryid = db.Column(db.Integer, primary_key = True)
  username = db.Column(db.String(120), nullable = False)
  querytext = db.Column(db.String(1000), nullable = False)
  queryresults = db.Column(db.String(1000), nullable = False)
  
  def save_to_db(self):
    db.session.add(self)
    db.session.commit()
  
  @classmethod
  def find_results_by_username(cls, username):
    return cls.query.filter_by(username = username).with_entities(SpellHistoryModel.queryid,  
      SpellHistoryModel.querytext,
      SpellHistoryModel.queryresults).all()


class LoggingModel(db.Model):
  __tablename__ = 'logging'

  id = db.Column(db.Integer, primary_key = True)
  username = db.Column(db.String(120), nullable = False)
  log_type = db.Column(db.String(120), nullable = False)
  message = db.Column(db.String(120), nullable = False)
  ip = db.Column(db.String(120), nullable = False)
  timestamp = db.Column(db.String(120), nullable = False)
  
  def save_to_db(self):
    db.session.add(self)
    db.session.commit()
