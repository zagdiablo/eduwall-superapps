from flask import Blueprint, request, url_for, flash, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from . import db
from .models import User, Kelas, Dosen, Mahasiswa


dosen_views = Blueprint("dosen_views", __name__)


"""
########## BAGIAN OTENTIKASI DOSEN ##########
"""


@dosen_views.get("/dosen_login")
def dosen_login():
    return render_template("dosen.html")


@dosen_views.post("/handle_dosen_login")
def handle_dosen_login():
    username = request.form.get("username")
    password = request.form.get("password")

    to_login_dosen = User.query.filter(User.username == username).first()

    if to_login_dosen:
        if to_login_dosen.role != "dosen":
            flash(f"Username atau Password salah.", category="error")
            return redirect("/dosen_loging")

        if check_password_hash(to_login_dosen.password, password):
            login_user(to_login_dosen)
            return redirect("/dosen_dashboard")

    flash(
        f"Terjadi kesalahan pada server, silahkan hubungi developer.", category="error"
    )
    return redirect("/dosen_login")


"""
########## BAGIAN VIEWS dosen ##########
"""


@dosen_views.get("/dosen_dashboard")
@login_required
def dosen_dashboard():
    all_kelas = Kelas.query.all()
    dosen = User.query.get(current_user.get_id())
    username = dosen.username

    return render_template(
        "modules/dosen_templates/dosen_dashboard.html",
        username=username,
        all_kelas=all_kelas,
    )
