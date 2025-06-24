from flask import Flask, render_template, request, redirect, url_for, flash
from flask import session
import time
import re
import os
import json
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

# Питання для тесту з вибором відповіді
QUIZ_QUESTIONS = [
    {
        "question": "Який протокол забезпечує захищене з'єднання у вебі?",
        "options": ["HTTP", "FTP", "SSH", "HTTPS"],
        "answer": 3,
    },
    {
        "question": "Що таке фішинг?",
        "options": [
            "Збирання даних за допомогою шкідливих листів",
            "Резервне копіювання інформації",
            "Захист від вірусів",
            "Процес шифрування повідомлень",
        ],
        "answer": 0,
    },
    {
        "question": "Яке з перелічених є прикладом сильної автентифікації?",
        "options": [
            "Пароль з 4 цифр",
            "Пароль та двофакторна перевірка",
            "Єдине запитання безпеки",
            "Лише ім'я користувача",
        ],
        "answer": 1,
    },
    {
        "question": "Що робить брандмауер?",
        "options": [
            "Оптимізує швидкість мережі",
            "Фільтрує небажаний мережевий трафік",
            "Зберігає паролі користувачів",
            "Створює резервні копії",
        ],
        "answer": 1,
    },
    {
        "question": "Чим небезпечні загальнодоступні Wi-Fi мережі?",
        "options": [
            "Вони мають низьку швидкість",
            "Можуть перехоплювати ваші дані",
            "Вони недоступні у святкові дні",
            "Викликають перевитрату мобільного трафіку",
        ],
        "answer": 1,
    },
    {
        "question": "Яке розширення зазвичай мають виконувані файли у Windows?",
        "options": [".txt", ".doc", ".exe", ".png"],
        "answer": 2,
    },
    {
        "question": "Який метод атаки націлений на вгадування пароля?",
        "options": ["SQL Injection", "Brute Force", "Phishing", "DDoS"],
        "answer": 1,
    },
    {
        "question": "Що з перерахованого є прикладом соціальної інженерії?",
        "options": [
            "Використання складного шифрування",
            "Обман користувача для отримання даних",
            "Атака на сервер за допомогою ботнету",
            "Регулярне оновлення ПЗ",
        ],
        "answer": 1,
    },
    {
        "question": "Який принцип безпеки означає розмежування доступу?",
        "options": [
            "Надійність",
            "Конфіденційність",
            "Резервування",
            "Принцип найменших привілеїв",
        ],
        "answer": 3,
    },
    {
        "question": "Що таке двофакторна аутентифікація?",
        "options": [
            "Перевірка двох паролів",
            "Використання пароля та додаткового підтвердження",
            "Аутентифікація двох користувачів",
            "Реєстрація на двох сайтах",
        ],
        "answer": 1,
    },
    {
        "question": "Чому слід регулярно оновлювати програмне забезпечення?",
        "options": [
            "Щоб звільнити місце на диску",
            "Щоб покращити захист від вразливостей",
            "Щоб вимкнути брандмауер",
            "Щоб зменшити використання пам'яті",
        ],
        "answer": 1,
    },
    {
        "question": "Яке з наведеного є прикладом складного пароля?",
        "options": ["123456", "password", "Qw!8_zR9", "qwerty"],
        "answer": 2,
    },
    {
        "question": "Що означає абревіатура VPN?",
        "options": [
            "Virtual Private Network",
            "Very Personal Notebook",
            "Visual Protocol Number",
            "Verified Password Name",
        ],
        "answer": 0,
    },
    {
        "question": "Яке з перерахованого допомагає уникнути зараження вірусом?",
        "options": [
            "Відкривати всі вкладення з листів",
            "Використовувати антивірус і не запускати невідомі файли",
            "Ніколи не вимикати комп'ютер",
            "Видаляти системні файли",
        ],
        "answer": 1,
    },
    {
        "question": "Чим корисне шифрування даних?",
        "options": [
            "Підвищує швидкість Інтернету",
            "Дозволяє приховати інформацію від сторонніх",
            "Зменшує вагу файлів",
            "Видаляє старі дані",
        ],
        "answer": 1,
    },
    {
        "question": "Як називається програма, що видає себе за легальну, але містить шкідливий код?",
        "options": ["Черв'як", "Троян", "Антивірус", "Проксі"],
        "answer": 1,
    },
    {
        "question": "Що робить атака типу DDoS?",
        "options": [
            "Змінює права доступу користувачів",
            "Блокує роботу сервера великою кількістю запитів",
            "Шифрує всі файли на диску",
            "Проводить фішингову розсилку",
        ],
        "answer": 1,
    },
    {
        "question": "Який інструмент використовується для збереження паролів у зашифрованому вигляді?",
        "options": ["Менеджер паролів", "Текстовий файл", "Блокнот", "Браузер"],
        "answer": 0,
    },
    {
        "question": "Який з перелічених варіантів є фактором автентифікації 'щось, що ви маєте'?",
        "options": [
            "Пароль",
            "Скан відбитку пальця",
            "Смартфон з кодом",
            "Ім'я користувача",
        ],
        "answer": 2,
    },
    {
        "question": "Що таке резервне копіювання даних?",
        "options": [
            "Процес видалення непотрібних файлів",
            "Створення копії даних для відновлення",
            "Шифрування інформації",
            "Оновлення операційної системи",
        ],
        "answer": 1,
    },
]

app = Flask(__name__)
app.config["SECRET_KEY"] = "your_secret_key"
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///cybercrime.db"

# Ініціалізація БД та логіну
db.init_app(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# File to store user credentials so they can be easily edited
CRED_FILE = "credentials.json"


def load_credentials():
    """Load username/password hashes from the credentials file."""
    if os.path.exists(CRED_FILE):
        with open(CRED_FILE, "r", encoding="utf-8") as f:
            try:
                return json.load(f)
            except json.JSONDecodeError:
                return {}
    return {}


def save_credentials(creds):
    """Persist credential dictionary back to the file."""
    with open(CRED_FILE, "w", encoding="utf-8") as f:
        json.dump(creds, f, ensure_ascii=False, indent=2)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        creds = load_credentials()
        if username in creds or User.query.filter_by(username=username).first():
            flash("Користувач вже існує")
            return redirect(url_for("register"))

        password_hash = generate_password_hash(password)
        # Update file-based credentials
        creds[username] = {"password_hash": password_hash, "is_admin": False}
        save_credentials(creds)

        # Also keep in the database for Flask-Login
        new_user = User(username=username, password_hash=password_hash)
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

        creds = load_credentials()
        cred = creds.get(username)
        user = None
        if cred and check_password_hash(cred["password_hash"], password):
            # Ensure corresponding DB user exists
            user = User.query.filter_by(username=username).first()
            if not user:
                user = User(
                    username=username,
                    password_hash=cred["password_hash"],
                    is_admin=cred.get("is_admin", False),
                )
                db.session.add(user)
                db.session.commit()

        if user:
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


@app.route("/practice")
@login_required
def practice():
    return render_template("practice.html")


@app.route("/theory")
@login_required
def theory():
    return render_template("theory.html")


@app.route("/quiz", methods=["GET", "POST"])
@login_required
def quiz():
    score = None
    if request.method == "GET":
        session["start_quiz"] = time.time()
    if request.method == "POST":
        score = 0
        for idx, q in enumerate(QUIZ_QUESTIONS):
            answer = request.form.get(f"q{idx}")
            if answer and int(answer) == q["answer"]:
                score += 1
        time_spent = time.time() - session.get("start_quiz", time.time())
        log = TestLog(
            user_id=current_user.id,
            test_name="quiz",
            attempts=1,
            successes=score,
            fails=len(QUIZ_QUESTIONS) - score,
            time_spent=time_spent,
        )
        db.session.add(log)
        db.session.commit()
    return render_template("quiz.html", questions=QUIZ_QUESTIONS, score=score)


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
    return render_template("index.html")


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


def initialize_credentials():
    """Ensure credential file and database contain at least the admin user."""
    creds = load_credentials()
    changed = False
    if "admin" not in creds:
        creds["admin"] = {
            "password_hash": generate_password_hash("admin"),
            "is_admin": True,
        }
        changed = True
    if changed:
        save_credentials(creds)

    # Sync users from credentials into DB
    for username, data in creds.items():
        if not User.query.filter_by(username=username).first():
            db.session.add(
                User(
                    username=username,
                    password_hash=data["password_hash"],
                    is_admin=data.get("is_admin", False),
                )
            )
    db.session.commit()


if __name__ == "__main__":
    with app.app_context():
        db.create_all()
        initialize_credentials()
    app.run(debug=True)
