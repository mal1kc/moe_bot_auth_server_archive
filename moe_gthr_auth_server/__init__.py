from flask import Flask, abort,jsonify, request
from .database_op import Admin, Kullanici, db, sha256_hash
app = Flask("moe_gatherer_server")
app.config.from_mapping(
    SECRET_KEY="secret key",
    SQLALCHEMY_DATABASE_URI="sqlite:///sunucu.db"
)

@app.cli.command("initdb")
def initdb_command():
  print("Veritabanı oluşturuluyor")
  db.create_all()
  print("Veritabanı oluşturuldu")
  if Kullanici.query.filter_by(k_adi="mal1kc").first() is None:
    db.session.add(Kullanici(k_adi="mal1kc",k_sifre_hash=sha256_hash("admin")))
  print("Admin eklendi")
  db.session.commit()
  print("Veritabanı oluşturuldu")

db.init_app(app)
@app.route("/",methods=["GET","POST"])
def anasayfa():
  return jsonify({"status":"OK"})

@app.route("/kayit",methods=["GET","POST"])
def kayit(model:Kullanici=None):
  if request.method == "POST":
    print(request.form)

  else:
    
    all_users = Kullanici.query.all()
    return jsonify({"status":"ok","users":all_users})

def not_found():
  return jsonify({"status":"not_found"}),404

def is_admin(f):
  def wrapper(*args,**kwargs):
    if request.headers.get("Authorization") is None:
      return jsonify({"status":"not_authorized"}),401
    else:
      admin = Admin.query.filter_by(a_adi=request.authorization.username).first()
      if admin is None:
        return not_found()
      if request.authorization.password != admin.a_sifre_hash:
        return not_found()
      else:
        return f(*args,**kwargs)
  wrapper.__name__ = f.__name__
  return wrapper