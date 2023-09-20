from flask import Flask
from flask_wtf import CSRFProtect
from flask_login import login_manager
from flask_sqlalchemy import SQLAlchemy

from . import config


app = Flask(__name__)
db = SQLAlchemy()


def create_app():
    # jangan lupa ganti config sebelum deploy
    app.config.from_object(config.Development)

    # daftar blueprint views pada web application
    from .public_views import public_views

    app.register_blueprint(public_views, url_prefix="/")

    with app.app_context():
        db.init_app(app)
        db.create_all()

    csrf = CSRFProtect(app)

    return app
