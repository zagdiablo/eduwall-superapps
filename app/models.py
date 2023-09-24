from flask_login import UserMixin
from . import db


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    nama_depan = db.Column(db.String(50), nullable=False)
    nama_belakang = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(100), nullable=False, unique=True)
    password = db.Column(db.String(100), nullable=False)
    role = db.Column(db.String(10), nullable=False, default="mahasiswa")
    is_dosen = db.relationship("Dosen", backref="is_dosen")
    is_mahasiswa = db.relationship("Mahasiswa", backref="is_mahasiswa")
    is_admin = db.relationship("Admin", backref="is_admin")


class Admin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Dosen(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nid = db.Column(db.String(50), nullable=True, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Mahasiswa(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    nim = db.Column(db.String(50), nullable=False, default="")
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


class Kelas(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    kode_kelas = db.Column(db.String(50), nullable=False, default="")
