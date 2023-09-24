from flask import Flask
from flask_wtf import CSRFProtect
from flask_login import LoginManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash

import os

from . import config


app = Flask(__name__)
db = SQLAlchemy()


def create_app():
    # jangan lupa ganti config sebelum deploy
    app.config.from_object(config.Development)

    # login manager
    login_manager = LoginManager(app)

    # daftar blueprint views pada web application
    from .public_views import public_views
    from .admin_views import admin_views
    from .dosen_views import dosen_views
    from .mahasiswa_views import mahasiswa_views

    app.register_blueprint(dosen_views, url_prefix="/")
    app.register_blueprint(admin_views, url_prefix="/")
    app.register_blueprint(public_views, url_prefix="/")
    app.register_blueprint(mahasiswa_views, url_prefix='/')

    # user loader
    from .models import User

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # database stuff
    if not check_database():
        with app.app_context():
            db.init_app(app)
            db.create_all()
            create_admin()

    csrf = CSRFProtect(app)

    return app


def check_database():
    """
    check if database is exist

    return True/False
    """

    if os.path.isfile("database/database.db"):
        return True
    return False


def create_admin():
    from .models import User, Admin

    users = User.query.all()
    for user in users:
        if user.role == "admin":
            print(f"[*] Akun admin sudah ada.")
            return

    new_user = User(
        username="admin",
        nama_depan="admin",
        nama_belakang="admin",
        password=generate_password_hash("password", "pbkdf2:sha256"),
        role="admin",
    )
    db.session.add(new_user)

    user_for_admin = User.query.get(1)

    new_admin = Admin(user_id=user_for_admin.id)
    db.session.add(new_admin)
    db.session.commit()

    print("[+] Akun admin utama berhasil dibuat.")
    return
