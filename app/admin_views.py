from flask import Blueprint, render_template, redirect, flash, url_for, request
from werkzeug.security import check_password_hash, generate_password_hash
from flask_login import login_user, logout_user, login_required, current_user

from .models import User, Kelas, Dosen, Mahasiswa
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
    return render_template('temp_main.html')


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


"""
########## BAGIAN HANDLE KELAS ##########
"""


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

    check_if_kelas_already_exist = Kelas.query.filter(
        Kelas.kode_kelas == kode_kelas
    ).first()
    if check_if_kelas_already_exist:
        flash(f"Kelas {kode_kelas} duah ada!")
        return redirect("/admin_dashboard")

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

    to_delete_kelas = Kelas.query.get(int(to_delete_kelas_id))

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


@admin_views.post("/handle_edit_kelas")
@login_required
def handle_edit_kelas():
    check_if_admin()

    kelas_id = request.form.get("to_edit_kelas_id")
    to_edit_kode_kelas = request.form.get("to_edit_kode_kelas")
    to_edit_kelas = Kelas.query.get(int(kelas_id))

    if to_edit_kelas:
        previous_kode_kelas = to_edit_kelas.kode_kelas
        to_edit_kelas.kode_kelas = to_edit_kode_kelas
        db.session.commit()
        flash(
            f"kelas {previous_kode_kelas} berhasil diganti menjadi {to_edit_kelas.kode_kelas}",
            category="success",
        )
        return redirect("/admin_dashboard")

    flash(f"Terjadi kelashan saat mengubah data")
    return redirect("/admin_dashboard")


"""
########## BAGIAN HANDLE DOSEN ##########
"""


@admin_views.get("/get_data_dosen")
@login_required
def get_data_dosen():
    check_if_admin()
    all_dosen = User.query.filter(User.role == "dosen")
    return render_template(
        "modules/admin_templates/dashboard_list_dosen.html", all_dosen=all_dosen
    )


@admin_views.post("/handle_tambah_dosen")
@login_required
def handle_tambah_dosen():
    check_if_admin()

    dosen_username = request.form.get("username")
    dosen_nama_depan = request.form.get("nama_depan")
    dosen_nama_belakang = request.form.get("nama_belakang")
    password = request.form.get("password")
    re_password = request.form.get("re-password")

    check_if_dosen_already_exist = User.query.filter(
        User.username == dosen_username
    ).first()

    if check_if_dosen_already_exist:
        flash(f"dosen dengan id {dosen_username} sudah ada.", category="error")
        return redirect("/admin_dashboard")

    if password != re_password:
        flash(f"Password tidak sesuai", category="error")
        return redirect("/admin_dashboard")

    new_user = User(
        username=dosen_username,
        nama_depan=dosen_nama_depan,
        nama_belakang=dosen_nama_belakang,
        password=generate_password_hash(password, "pbkdf2:sha256"),
        role="dosen",
    )
    db.session.add(new_user)
    db.session.commit()

    dosen_account = User.query.filter(User.username == dosen_username).first()

    new_dosen = Dosen(nid="-", user_id=dosen_account.id)
    db.session.add(new_dosen)
    db.session.commit()

    flash(f"berhasi membuat akun dosen {dosen_account.username}", category="success")
    return redirect("/get_data_dosen")


@admin_views.post("/handle_delete_dosen")
@login_required
def handle_delete_dosen():
    check_if_admin()

    to_delete_dosen_id = request.form.get("to_delete_dosen_id")

    to_delete_dosen_data = Dosen.query.filter(
        Dosen.user_id == int(to_delete_dosen_id)
    ).first()
    to_delete_dosen_account = User.query.get(int(to_delete_dosen_id))

    if to_delete_dosen_data:
        db.session.delete(to_delete_dosen_data)

    if to_delete_dosen_account:
        old_dosen_username = to_delete_dosen_account.username
        db.session.delete(to_delete_dosen_account)

    db.session.commit()
    flash(f"berhasil menghapus data dosen {old_dosen_username}", category="success")
    return redirect("/get_data_dosen")


@admin_views.post("/handle_edit_dosen")
@login_required
def handle_edit_dosen():
    check_if_admin()

    dosen_id = request.form.get("to_edit_dosen_id")
    dosen_username = request.form.get("dosen_username")
    dosen_nama_depan = request.form.get("dosen_nama_depan")
    dosen_nama_belakang = request.form.get("dosen_nama_belakang")
    dosen_password = request.form.get("dosen_password")
    re_dosen_password = request.form.get("re_dosen_password")

    to_edit_dosen_account = User.query.get(int(dosen_id))
    # TODO handle edit dosen data
    to_edit_dosen_data = Dosen.query.filter(Dosen.user_id == int(dosen_id)).first()
    old_dosen_username = to_edit_dosen_account.username

    if to_edit_dosen_account:
        to_edit_dosen_account.username = dosen_username
        to_edit_dosen_account.nama_depan = dosen_nama_depan
        to_edit_dosen_account.nama_belakang = dosen_nama_belakang

    if dosen_password:
        if dosen_password == re_dosen_password:
            to_edit_dosen_account.password = generate_password_hash(
                dosen_password, "pbkdf2:sha256"
            )

    db.session.commit()
    flash(
        f"berhasil mengubah data {old_dosen_username} menjadi {to_edit_dosen_account.username}"
    )
    return redirect("/get_data_dosen")


"""
########### BAGIAN HANDLE MAHASISWA ##########
"""


@admin_views.get("/get_data_mahasiswa")
@login_required
def get_data_mahasiswa():
    check_if_admin()
    all_mahasiswa = User.query.filter(User.role == "mahasiswa")
    return render_template(
        "modules/admin_templates/dashboard_list_mahasiswa.html",
        all_mahasiswa=all_mahasiswa,
    )


@admin_views.post("/handle_tambah_mahasiswa")
@login_required
def handle_tambah_mahasiswa():
    check_if_admin()

    mahasiswa_username = request.form.get("username")
    mahasiswa_nama_depan = request.form.get("nama_depan")
    mahasiswa_nama_belakang = request.form.get("nama_belakang")
    password = request.form.get("password")
    re_password = request.form.get("re-password")

    check_if_mahasiswa_already_exist = User.query.filter(
        User.username == mahasiswa_username
    ).first()

    if check_if_mahasiswa_already_exist:
        flash(f"Mahasiswa ini telah terdaftar.", category="error")
        return redirect("/admin_dashboard")

    if password != re_password:
        flash(f"password tidak sesuai", category="error")
        return redirect("/admin_dashboard")

    new_user = User(
        username=mahasiswa_username,
        nama_depan=mahasiswa_nama_depan,
        nama_belakang=mahasiswa_nama_belakang,
        password=generate_password_hash(password, "pbkdf2:sha256"),
        role="mahasiswa",
    )
    db.session.add(new_user)
    db.session.commit()

    mahasiswa_account = User.query.filter(User.username == mahasiswa_username).first()

    new_mahsiswa = Mahasiswa(nim="-", user_id=mahasiswa_account.id)
    db.session.add(new_mahsiswa)
    db.session.commit()

    flash(
        f"berhasi membuat akun mahasiswa {mahasiswa_account.username}",
        category="success",
    )
    return redirect("/get_data_mahasiswa")


@admin_views.post("/handle_delete_mahasiswa")
@login_required
def handle_delete_mahasiswa():
    check_if_admin()

    to_delete_mahasiswa_id = request.form.get("to_delete_mahasiswa_id")

    to_delete_mahasiswa_data = Mahasiswa.query.filter(
        Mahasiswa.user_id == int(to_delete_mahasiswa_id)
    ).first()
    to_delete_mahasiswa_account = User.query.get(int(to_delete_mahasiswa_id))

    if to_delete_mahasiswa_data:
        db.session.delete(to_delete_mahasiswa_data)

    if to_delete_mahasiswa_account:
        old_mahasiswa_username = to_delete_mahasiswa_account.username
        db.session.delete(to_delete_mahasiswa_account)

    db.session.commit()
    flash(
        f"berhasil menghapus data mahsiswa {old_mahasiswa_username}", category="success"
    )
    return redirect("/get_data_mahasiswa")


@admin_views.post("/handle_edit_mahasiswa")
@login_required
def handle_edit_mahasiswa():
    check_if_admin()

    mahasiswa_id = request.form.get("to_edit_mahasiswa_id")
    mahasiswa_username = request.form.get("mahasiswa_username")
    mahasiswa_nama_depan = request.form.get("mahasiswa_nama_depan")
    mahasiswa_nama_belakang = request.form.get("mahasiswa_nama_belakang")
    mahasiswa_password = request.form.get("mahasiswa_password")
    re_mahasiswa_password = request.form.get("re_mahasiswa_password")

    to_edit_mahasiswa_account = User.query.get(int(mahasiswa_id))
    # TODO handle edit mahasiswa data
    to_edit_mahasiswa_data = Mahasiswa.query.filter(
        Mahasiswa.user_id == int(mahasiswa_id)
    ).first()
    old_mahasiswa_username = to_edit_mahasiswa_account.username

    if to_edit_mahasiswa_account:
        to_edit_mahasiswa_account.username = mahasiswa_username
        to_edit_mahasiswa_account.nama_depan = mahasiswa_nama_depan
        to_edit_mahasiswa_account.nama_belakang = mahasiswa_nama_belakang

    if mahasiswa_password:
        if mahasiswa_password == re_mahasiswa_password:
            to_edit_mahasiswa_account.password = generate_password_hash(
                mahasiswa_password, "pbkdf2:sha256"
            )

    db.session.commit()
    flash(
        f"berhasil mengubah data {old_mahasiswa_username} menjadi {to_edit_mahasiswa_account.username}"
    )
    return redirect("/get_data_mahasiswa")
