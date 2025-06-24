from flask import Flask, render_template, request, redirect, url_for, flash
from flask import session
import time
import re
from datetime import datetime
from models import db, User, TestLog  # <-- додай TestLog тут!
from popular_passwords_600 import POPULAR_PASSWORDS_600

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cybercrime.db"

# Ініціалізація БД та логіну
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("Користувач вже існує")
            return redirect(url_for("register"))
        new_user = User(
            username=username, password_hash=generate_password_hash(password)
        )
        db.session.add(new_user)
        db.session.commit()
        flash("Реєстрація успішна")
        return redirect(url_for("login"))
    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password_hash, password):
            login_user(user)
            return redirect(
                url_for("admin_dashboard" if user.is_admin else "dashboard")
            )
        flash("Невірні дані")
    return render_template("login.html")


@app.route("/dashboard")
@login_required
def dashboard():
    pages = ["test1.html", "test2.html", "test3.html"]
    return render_template("dashboard.html", pages=pages)


@app.route("/admin")
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash("Доступ заборонено")
        return redirect(url_for("dashboard"))
    users = User.query.all()
    return render_template("admin.html", users=users)


@app.route("/admin/add", methods=["POST"])
@login_required
def admin_add_user():
    if not current_user.is_admin:
        flash("Доступ заборонено")
        return redirect(url_for("dashboard"))
    username = request.form["username"]
    password = request.form["password"]
    is_admin = True if request.form.get("is_admin") else False
    if User.query.filter_by(username=username).first():
        flash("Користувач вже існує")
    else:
        user = User(
            username=username,
            password_hash=generate_password_hash(password),
            is_admin=is_admin,
        )
        db.session.add(user)
        db.session.commit()
        flash("Користувача додано")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/edit/<int:user_id>", methods=["GET", "POST"])
@login_required
def admin_edit_user(user_id):
    if not current_user.is_admin:
        flash("Доступ заборонено")
        return redirect(url_for("dashboard"))
    user = User.query.get_or_404(user_id)
    if request.method == "POST":
        user.username = request.form["username"]
        if request.form["password"]:
            user.password_hash = generate_password_hash(request.form["password"])
        user.is_admin = True if request.form.get("is_admin") else False
        db.session.commit()
        flash("Дані оновлено")
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_user.html", user=user)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/test1.html", methods=["GET", "POST"])
@login_required
def test1():
    result = None
    if request.method == "GET":
        session["start_test1"] = time.time()
    if request.method == "POST":
        login = request.form.get("login", "")
        # ... логіка тесту ...
        time_spent = time.time() - session.get("start_test1", time.time())
        success = 1 if "' OR '1'='1" in login or '" OR "1"="1' in login else 0
        fail = 1 - success
        # Логування спроби
        log = TestLog(
            user_id=current_user.id,
            test_name="test1",
            attempts=1,
            successes=success,
            fails=fail,
            time_spent=time_spent,
        )
        db.session.add(log)
        db.session.commit()
    return render_template("test1.html", result=result)


# XSS — пам'ятай, що це для навчання, тут реально вставляється raw HTML!
guestbook = []

guestbook = []


@app.route("/test2.html", methods=["GET", "POST"])
@login_required
def test2():
    if request.method == "GET":
        session["start_test2"] = time.time()
    if request.method == "POST":
        message = request.form.get("message", "")
        guestbook.append(message)
        time_spent = time.time() - session.get("start_test2", time.time())
        # Успішна XSS — якщо в повідомленні є <script>
        success = 1 if "<script" in message.lower() else 0
        fail = 1 - success
        # Логування спроби
        log = TestLog(
            user_id=current_user.id,
            test_name="test2",
            attempts=1,
            successes=success,
            fails=fail,
            time_spent=time_spent,
        )
        db.session.add(log)
        db.session.commit()
    return render_template("test2.html", messages=guestbook)


from popular_passwords_600 import POPULAR_PASSWORDS_600

VALID_USERS = ["user_fake1", "user_fake2", "user_fake3"]


from popular_passwords_600 import POPULAR_PASSWORDS_600
import re

VALID_USERS = ["user_fake1", "user_fake2", "user_fake3"]


def password_strength(password):
    length = len(password)
    score = 0
    if length >= 8:
        score += 30
    if re.search(r"[A-Z]", password):
        score += 20
    if re.search(r"[a-z]", password):
        score += 20
    if re.search(r"\d", password):
        score += 15
    if re.search(r"[^A-Za-z0-9]", password):
        score += 15
    if length >= 12:
        score += 10
    if score > 100:
        score = 100
    return score


@app.route("/test3.html", methods=["GET", "POST"])
@login_required
def test3():
    result = None
    password_analysis = None

    if request.method == "GET":
        session["start_test3"] = time.time()

    if request.method == "POST":
        login = request.form.get("login", "")
        password = request.form.get("password", "")
        strength = password_strength(password)
        time_spent = time.time() - session.get("start_test3", time.time())

        # Перевірка основного входу (Brute force лабораторія)
        if login in VALID_USERS and password in POPULAR_PASSWORDS_600:
            result = f"Вхід успішний! Ви тестували слабкий акаунт {login}."
            success = 1
            fail = 0
        else:
            result = "Невірний логін або пароль."
            success = 0
            fail = 1

        # Аналіз складності (незалежно від логіна)
        if password in POPULAR_PASSWORDS_600 or strength < 50:
            password_analysis = f"Для захисту це поганий пароль, його складність {strength}%, не використовуйте його в своїх облікових записах."
        else:
            password_analysis = (
                f"Для захисту це чудовий пароль, його складність {strength}%."
            )

        # Логування
        log = TestLog(
            user_id=current_user.id,
            test_name="test3",
            attempts=1,
            successes=success,
            fails=fail,
            time_spent=time_spent,
        )
        db.session.add(log)
        db.session.commit()

    return render_template(
        "test3.html", result=result, password_analysis=password_analysis
    )


@app.route("/test4.html", methods=["GET", "POST"])
@login_required
def test4():

    phish_indices = {0, 3}
    explanations = [
        "admin@school.edu.ua: Підозрілий лист із проханням терміново ввести дані (типова ознака фішингу).",
        "director@school.edu.ua: Звичайне повідомлення від директора школи.",
        "pupil231@gmail.com: Звичайне прохання від учня.",
        "info@admin-school.com: Незнайомий e-mail, погрози блокування, заклик до авторизації — це ознаки фішингу.",
    ]
    result = details = None

    if request.method == "GET":
        session["start_test4"] = time.time()

    if request.method == "POST":
        selected = set(map(int, request.form.getlist("phish")))
        time_spent = time.time() - session.get("start_test4", time.time())

        if selected == phish_indices:
            result = "Правильно! Ви виявили всі фішингові листи."
            success = 1
            fail = 0
        else:
            result = f"Не всі відповіді вірні. Ви відмітили: {', '.join(str(i+1) for i in selected)}"
            success = 0
            fail = 1

        details = "<ul>"
        for idx, txt in enumerate(explanations):
            style = "color:red;" if idx in phish_indices else "color:green;"
            details += f'<li style="{style}">{txt}</li>'
        details += "</ul>"

        # Логування
        log = TestLog(
            user_id=current_user.id,
            test_name="test4",
            attempts=1,
            successes=success,
            fails=fail,
            time_spent=time_spent,
        )
        db.session.add(log)
        db.session.commit()

    return render_template("test4.html", result=result, details=details)


from datetime import datetime


@app.route("/admin/report", methods=["GET", "POST"])
@login_required
def admin_report():
    if not current_user.is_admin:
        flash("Доступ заборонено")
        return redirect(url_for("dashboard"))

    users = User.query.all()
    logs = []
    start_date = end_date = None
    selected_user_id = None

    if request.method == "POST":
        start_date = request.form.get("start_date")
        end_date = request.form.get("end_date")
        selected_user_id = request.form.get("user_id")
        query = TestLog.query
        if start_date:
            query = query.filter(
                TestLog.timestamp >= datetime.fromisoformat(start_date)
            )
        if end_date:
            query = query.filter(TestLog.timestamp <= datetime.fromisoformat(end_date))
        if selected_user_id and selected_user_id != "all":
            query = query.filter(TestLog.user_id == int(selected_user_id))
        logs = query.all()
    else:
        logs = TestLog.query.all()

    # Зведення по користувачах/тестах
    summary = {}
    for log in logs:
        key = (log.user.username, log.test_name)
        if key not in summary:
            summary[key] = {
                "attempts": 0,
                "successes": 0,
                "fails": 0,
                "time_spent": 0,
                "dates": [],
            }
        summary[key]["attempts"] += log.attempts
        summary[key]["successes"] += log.successes
        summary[key]["fails"] += log.fails
        summary[key]["time_spent"] += log.time_spent
        summary[key]["dates"].append(log.timestamp.strftime("%Y-%m-%d %H:%M:%S"))

    return render_template(
        "admin_report.html",
        users=users,
        summary=summary,
        start_date=start_date,
        end_date=end_date,
        selected_user_id=selected_user_id,
    )


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        # Додає адміністратора, якщо його ще нема
        if not User.query.filter_by(username="admin").first():
            admin = User(
                username="admin",
                password_hash=generate_password_hash("admin"),
                is_admin=True,
            )
            db.session.add(admin)
            db.session.commit()
    app.run(debug=True)
