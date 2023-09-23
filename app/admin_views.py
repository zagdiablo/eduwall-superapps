from flask import Blueprint, render_template, redirect, flash, url_for, request
from werkzeug.security import check_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from .models import User, Kelas
from . import db


admin_views = Blueprint("admin_views", __name__)


"""
########## FUNGSI ##########
"""


def check_if_admin():
    check_user_is_admin = User.query.get(current_user.get_id())
    if check_user_is_admin:
        if check_user_is_admin.role != "admin":
            print("user is not admin")
            return "<h1> halaman login dosen & mahasiswa </h1>"


"""
########## BAGIAN OTENTIKASI ADMIN ##########
"""


# TODO temporary, delete before release
@admin_views.get("/")
def main():
    return redirect("/admin_login")


@admin_views.get("/admin_login")
def admin_login():
    check_if_admin()

    check_user_is_admin = User.query.get(current_user.get_id())
    if check_user_is_admin:
        if check_user_is_admin.role == "admin":
            print("user is admin, redirecting")
            return redirect("/admin_dashboard")

    return render_template("admin.html")


@admin_views.post("/handle_admin_login")
def handle_admin_login():
    username = request.form.get("username")
    password = request.form.get("password")

    to_login_admin = User.query.filter(User.username == username).first()

    if to_login_admin:
        if to_login_admin.role != "admin":
            flash(f"Username atau Password salah.", category="error")
            return redirect("/admin_loging")

        if check_password_hash(to_login_admin.password, password):
            login_user(to_login_admin)
            return redirect("/admin_dashboard")

    flash(
        f"Terjadi kesalahan pada server, silahkan hubungi developer.", category="error"
    )
    return redirect("/admin_login")


@admin_views.get("/admin_logout")
@login_required
def admin_logout():
    check_if_admin()
    logout_user()
    return redirect("/admin_login")


"""
########## BAGIAN VIEWS ADMIN ##########
"""


@admin_views.get("/admin_dashboard")
@login_required
def admin_dashboard():
    check_if_admin()

    all_kelas = Kelas.query.all()
    admin = User.query.get(current_user.get_id())
    username = admin.username

    return render_template(
        "modules/admin_templates/dashboard.html", username=username, all_kelas=all_kelas
    )


@admin_views.get("/get_data_kelas")
@login_required
def get_data_kelas():
    all_kelas = Kelas.query.all()

    return render_template(
        "modules/admin_templates/dashboard_list_kelas.html", all_kelas=all_kelas
    )


@admin_views.post("/handle_tambah_kelas")
@login_required
def handle_tambah_kelas():
    check_if_admin()

    kode_kelas = request.form.get("kode_kelas")

    new_kelas = Kelas(kode_kelas=kode_kelas)
    db.session.add(new_kelas)
    db.session.commit()

    admin = User.query.get(current_user.get_id())
    all_kelas = Kelas.query.all()

    username = admin.username

    return render_template(
        "modules/admin_templates/dashboard_list_kelas.html",
        username=username,
        all_kelas=all_kelas,
    )


@admin_views.post("/handle_delete_kelas")
@login_required
def handle_delete_kelas():
    check_if_admin()

    to_delete_kelas_id = request.form.get("to_delete_kelas_id")

    to_delete_kelas = Kelas.query.get(to_delete_kelas_id)

    if to_delete_kelas:
        flash(
            f"data kelas {to_delete_kelas.kode_kelas} berhasil dihapus.",
            category="success",
        )
        db.session.delete(to_delete_kelas)
        db.session.commit()
        return redirect("/admin_dashboard")

    flash(f"terjadi kesalahan, mungkin data kelas sudah di hapus", category="error")
    return redirect("/admin_dashboard")
