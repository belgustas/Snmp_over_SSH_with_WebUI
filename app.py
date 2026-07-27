# Flask + модели данных + utils для управления SSH-туннелями через веб-интерфейс
from flask import Flask, request, session, redirect, url_for, render_template, abort
from models import (
    Session as DbSession, SSHServer, Subsystem,
    Group, User, ClientIP, ServerAccessRule, RequestLog, AppSettings,
)
from auth_utils import check_password, hash_password
from bridge_manager import BridgeManager
from datetime import datetime

app = Flask(__name__)
app.secret_key = "ILoveCats"

# manager = глобальный экземпляр, который живёт всё время работы приложения
# все SSH-туннели хранятся тут. Если он упадёт — все туннели потеряются.
manager = BridgeManager()
manager.reload_from_db()  # загружаем то, что было сохранено в БД с прошлого запуска


@app.errorhandler(403)
def forbidden(error):
    # Просто показываем красивую страничку, когда оператор суёт нос не туда
    return render_template("403.html", username=session.get("username")), 403


# Проверка доступа
def login_required(view_func):
    # Ловушка для тех, кто зашёл на защищённый роут без логина
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)

    wrapped.__name__ = view_func.__name__
    return wrapped


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        db = DbSession()
        user = db.query(User).filter_by(username=username).first()

        # Проверяем три условия: юзер есть, пароль верный, учётка не истекла
        if user and check_password(password, user.password_hash) and not user.is_expired():
            session["username"] = username
            session["role"] = user.group.name  # admin или operator
            return redirect(url_for("dashboard"))
        else:
            # Один ответ для всех ошибок (security best practice: не говорим, был ли пользователь)
            return render_template("login.html", error="Неверный логин, пароль или истекшая учетная запись")
        db.close()
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("login"))


@app.route("/")
def index():
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    # Главная страница: показываем все серверы, юзеров, текущие сессии и разрешаем админам создавать новые
    db = DbSession()

    # Автоматически создаём AppSettings, если её нет — нужна минимально одна запись для конфига
    settings = db.query(AppSettings).first()
    if not settings:
        settings = AppSettings()
        db.add(settings)
        db.commit()

    # Собираем "плоскую" таблицу серверов для JS-таблицы в шаблоне
    # (каждый subsystem = отдельная строка, чтобы было видно, какие порты открыты)
    servers_table = []
    for server in db.query(SSHServer).all():
        for sub in server.subsystems:
            servers_table.append({
                "server_name": server.name, "host": server.host, "port": server.port,
                "subsystem": sub.name, "local_port": sub.local_port, "sub_id": sub.id,
                "server_id": server.id,
            })

    # Собираем всех пользователей, группы, IP, правила для формочек на фронте
    servers = db.query(SSHServer).all()
    groups = db.query(Group).all()
    users = db.query(User).all()
    client_ips = db.query(ClientIP).all()
    access_rules = db.query(ServerAccessRule).all()

    html = render_template(
        "dashboard.html",
        username=session["username"],
        servers_table=servers_table,
        sessions=manager.list_sessions(),  # текущие подключённые клиенты
        servers=servers, groups=groups, users=users,
        client_ips=client_ips, access_rules=access_rules,
        settings=settings,
        is_admin=session.get("role") == "admin",
    )
    db.close()
    return html


def admin_required(view_func):
    # Юзер должен быть залогинен И иметь роль admin
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)  # "нет доступа" для операторов
        return view_func(*args, **kwargs)

    wrapped.__name__ = view_func.__name__
    return wrapped


# Управление ssh туннелями
@app.route("/reload", methods=["POST"])
@admin_required
def reload_bridges():
    # Admin нажал "Перезагрузить" — перечитываем БД и запускаем/останавливаем мосты
    manager.reload_from_db()
    return redirect(url_for("dashboard"))


@app.route("/disconnect/<int:session_id>", methods=["POST"])
@admin_required
def disconnect(session_id):
    # Admin нажал "Отключить клиента" — дико отрываем соединение (сессию)
    manager.disconnect_session(session_id)
    return redirect(url_for("dashboard"))


# Управление ssh серверами
@app.route("/add_server", methods=["POST"])
@admin_required
def add_server():
    """
    Добавляет новый SSH-сервер в БД с параметрами подключения.
    Параметры из формы: name, host, port, proxy_username, proxy_password.
    """
    db = DbSession()
    server = SSHServer(
        name=request.form["name"],
        host=request.form["host"],
        port=int(request.form["port"]),
        proxy_username=request.form["proxy_username"],
        proxy_password=request.form["proxy_password"],
    )
    db.add(server)
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/add_subsystem", methods=["POST"])
@admin_required
def add_subsystem():
    """
    Добавляет новый subsystem (e.g., 'snmp', 'netconf') с локальным портом.
    Параметры: name, local_port, server_id.
    После добавления перезагружает мосты, чтобы запустить новый туннель.
    """
    db = DbSession()
    sub = Subsystem(
        name=request.form["name"],
        local_port=int(request.form["local_port"]),
        server_id=int(request.form["server_id"]),
    )
    db.add(sub)
    db.commit()
    db.close()
    manager.reload_from_db()  # Запускаем новый мост
    return redirect(url_for("dashboard"))


@app.route("/delete_subsystem/<int:sub_id>", methods=["POST"])
@admin_required
def delete_subsystem(sub_id):
    db = DbSession()
    sub = db.get(Subsystem, sub_id)
    if sub:
        manager.stop_bridge(sub.local_port)
        db.delete(sub)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_server/<int:server_id>", methods=["POST"])
@admin_required
def delete_server(server_id):
    db = DbSession()
    server = db.get(SSHServer, server_id)
    if server:
        for sub in list(server.subsystems):
            manager.stop_bridge(sub.local_port)
            db.delete(sub)
        for rule in list(server.access_rules):
            db.delete(rule)
        db.delete(server)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


# Управление пользователями и группами
@app.route("/add_group", methods=["POST"])
@admin_required
def add_group():
    # Просто заводим группу (admin, operator, и т.д.)
    db = DbSession()
    db.add(Group(name=request.form["name"]))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    # Новый юзер приложения (не путать с SSH-юзерами на удалённых серверах!)
    # Пароль хэшируем сразу
    db = DbSession()
    expires_raw = request.form.get("expires_at", "").strip()
    expires_at = datetime.strptime(expires_raw, "%Y-%m-%dT%H:%M") if expires_raw else None
    db.add(User(
        username=request.form["username"],
        password_hash=hash_password(request.form["password"]),
        group_id=int(request.form["group_id"]),
        expires_at=expires_at,
    ))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_user/<int:user_id>", methods=["POST"])
@admin_required
def delete_user(user_id):
    # Удаляем юзера вместе со ВСЕМИ его IP-адресами и правилами доступа
    db = DbSession()
    user = db.query(User).filter_by(id=user_id).first()
    if user:
        for ip in list(user.ip_addresses):
            for rule in list(ip.access_rules):
                db.delete(rule)
            db.delete(ip)
        db.delete(user)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


# Управление IP адресами и доступом
@app.route("/add_client_ip", methods=["POST"])
@admin_required
def add_client_ip():
    """
    Добавляет IP-адрес для пользователя с собственными учётными данными SSH.
    Параметры: ip_address, user_id, ssh_username (опционально), ssh_password (опционально), ssh_key_path (опционально).
    Если ни ssh_username ни ssh_key_path не заданы — используются учётные данные сервера.
    """
    db = DbSession()
    ssh_username = request.form.get("ssh_username", "").strip() or None
    ssh_password = request.form.get("ssh_password")
    ssh_key_path = request.form.get("ssh_key_path", "").strip() or None
    # Если нет ни username ни key_path, пароль не нужен
    if not ssh_username and not ssh_key_path:
        ssh_password = None
    db.add(ClientIP(
        ip_address=request.form["ip_address"],
        user_id=int(request.form["user_id"]),
        ssh_username=ssh_username,
        ssh_password=ssh_password,
        ssh_key_path=ssh_key_path,
    ))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/update_settings", methods=["POST"])
@admin_required
def update_settings():
    """
    Обновляет глобальные настройки приложения:
    - app_name: название приложения
    - logging_enabled: включить/отключить логирование
    - web_ui_port: порт для веб-интерфейса
    """
    db = DbSession()
    settings = db.query(AppSettings).first()
    if not settings:
        settings = AppSettings()
        db.add(settings)
    settings.app_name = request.form.get("app_name", "").strip() or "SSH Subsystem Proxy"
    settings.logging_enabled = request.form.get("logging_enabled") == "on"
    settings.web_ui_port = int(request.form.get("web_ui_port") or 8080)
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_client_ip/<int:ip_id>", methods=["POST"])
@admin_required
def delete_client_ip(ip_id):
    """
    Удаляет IP-адрес пользователя и все его правила доступа.
    """
    db = DbSession()
    ip = db.query(ClientIP).filter_by(id=ip_id).first()
    if ip:
        for rule in list(ip.access_rules):
            db.delete(rule)
        db.delete(ip)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/add_access_rule", methods=["POST"])
@admin_required
def add_access_rule():
    """
    Добавляет правило доступа: позволяет IP-адресу обращаться к конкретному SSH-серверу.
    Параметры: client_ip_id, server_id.
    """
    db = DbSession()
    db.add(ServerAccessRule(
        client_ip_id=int(request.form["client_ip_id"]),
        server_id=int(request.form["server_id"]),
    ))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/delete_access_rule/<int:rule_id>", methods=["POST"])
@admin_required
def delete_access_rule(rule_id):
    """Удаляет правило доступа."""
    db = DbSession()
    rule = db.query(ServerAccessRule).filter_by(id=rule_id).first()
    if rule:
        db.delete(rule)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/logs")
@login_required
def logs():
    # История подключений: последние 200 записей, от новых к старым
    # (логирование включается/отключается в /update_settings)
    db = DbSession()
    entries = (
        db.query(RequestLog)
        .order_by(RequestLog.connected_at.desc())
        .limit(200)
        .all()
    )
    html = render_template("logs.html", username=session["username"], entries=entries)
    db.close()
    return html


if __name__ == "__main__":
    # При запуске: читаем порт из БД (если есть AppSettings), иначе 8080
    db = DbSession()
    settings = db.query(AppSettings).first()
    port = settings.web_ui_port if settings else 8080
    db.close()
    app.run(host="0.0.0.0", port=port, debug=True)
