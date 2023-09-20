from flask import Blueprint, render_template, redirect, request, flash, url_for


public_views = Blueprint("public_views", __name__)


@public_views.get("/")
def main():
    return render_template("index.html")
