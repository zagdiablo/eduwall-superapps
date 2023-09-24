from flask import Blueprint, request, url_for, flash, redirect, render_template
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from . import db
from .models import User, Kelas, Dosen, Mahasiswa


mahasiswa_views = Blueprint("mahasiswa_views", __name__)


"""
########## BAGIAN OTENTIKASI MAHASISWA ##########
"""


@mahasiswa_views.get("/mahasiswa_login")
def mahasiswa_login():
    return render_template("mahasiswa.html")


@mahasiswa_views.post("/handle_mahasiswa_login")
def handle_mahasiswa_login():
    username = request.form.get("username")
    password = request.form.get("password")

    to_login_mahasiswa = User.query.filter(User.username == username).first()

    if to_login_mahasiswa:
        if to_login_mahasiswa.role != "mahasiswa":
            flash(f"Username atau Password salah.", category="error")
            return redirect("/mahasiswa_loging")

        if check_password_hash(to_login_mahasiswa.password, password):
            login_user(to_login_mahasiswa)
            return redirect("/mahasiswa_dashboard")

    flash(
        f"Terjadi kesalahan pada server, silahkan hubungi developer.", category="error"
    )
    return redirect("/mahasiswa_login")


"""
########## BAGIAN VIEWS MAHASISWA ##########
"""


@mahasiswa_views.get("/mahasiswa_dashboard")
@login_required
def mahasiswa_dashboard():
    all_kelas = Kelas.query.all()
    mahasiswa = User.query.get(current_user.get_id())
    username = mahasiswa.username

    return render_template(
        "modules/mahasiswa_templates/mahasiswa_dashboard.html",
        username=username,
        all_kelas=all_kelas,
    )
