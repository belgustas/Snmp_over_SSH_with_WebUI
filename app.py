from flask import Flask, request, session, redirect, url_for, render_template, abort

from models import (
    Session as DbSession, SSHServer, Subsystem,
    Group, User, ClientIP, ServerAccessRule, RequestLog, AppSettings,
)   
from auth_utils import check_password, hash_password
from bridge_manager import BridgeManager
from datetime import datetime

app = Flask(__name__)
app.secret_key = "ILoveCats"  # нужен для подписи cookie

manager = BridgeManager()
manager.reload_from_db()


@app.errorhandler(403)
def forbidden(error):
    return render_template("403.html", username=session.get("username")), 403


def login_required(view_func):
    """Обёртка: перенаправляет на /login, если пользователь не вошёл."""
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


        if user and check_password(password, user.password_hash) and not user.is_expired():
            session["username"] = username
            session["role"] = user.group.name  # НОВОЕ: "admin" или "operator"
            return redirect(url_for("dashboard"))
        else:
            return render_template("login.html", error="Неверный логин, пароль или истекшая учетная запись")
        db.close()
    return render_template("login.html", error=None)


@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("role", None)
    return redirect(url_for("login"))


@app.route("/dashboard")
@login_required
def dashboard():
    db = DbSession()
    settings = db.query(AppSettings).first()
    if not settings:
        settings = AppSettings()
        db.add(settings)
        db.commit()
    servers_table = []
    for server in db.query(SSHServer).all():
        for sub in server.subsystems:
            servers_table.append({
                "server_name": server.name, "host": server.host, "port": server.port,
                "subsystem": sub.name, "local_port": sub.local_port, "sub_id": sub.id,
                "server_id": server.id,
            })

    servers = db.query(SSHServer).all()
    groups = db.query(Group).all()
    users = db.query(User).all()
    client_ips = db.query(ClientIP).all()
    access_rules = db.query(ServerAccessRule).all()

    html = render_template(
        "dashboard.html",
        username=session["username"],
        servers_table=servers_table,
        sessions=manager.list_sessions(),
        servers=servers, groups=groups, users=users,
        client_ips=client_ips, access_rules=access_rules,
        settings=settings,
        is_admin=session.get("role") == "admin",
    )
    db.close()   # закрываем ПОСЛЕ того, как шаблон уже всё прочитал
    return html


def admin_required(view_func):
    """Обёртка: пускает дальше только пользователей с ролью admin."""
    def wrapped(*args, **kwargs):
        if "username" not in session:
            return redirect(url_for("login"))
        if session.get("role") != "admin":
            abort(403)
        return view_func(*args, **kwargs)
    wrapped.__name__ = view_func.__name__
    return wrapped

@app.route("/reload", methods=["POST"])
@admin_required
def reload_bridges():
    manager.reload_from_db()
    return redirect(url_for("dashboard"))

@app.route("/disconnect/<int:session_id>", methods=["POST"])
@admin_required
def disconnect(session_id):
    manager.disconnect_session(session_id)
    return redirect(url_for("dashboard"))

@app.route("/add_server", methods=["POST"])
@admin_required
def add_server():
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
    db = DbSession()
    sub = Subsystem(
        name=request.form["name"],
        local_port=int(request.form["local_port"]),
        server_id=int(request.form["server_id"]),
    )
    db.add(sub)
    db.commit()
    db.close()
    manager.reload_from_db()
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

@app.route("/add_group", methods=["POST"])
@admin_required
def add_group():
    db = DbSession()
    db.add(Group(name=request.form["name"]))
    db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/add_user", methods=["POST"])
@admin_required
def add_user():
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
    db = DbSession()
    user = db.get(User, user_id)
    if user:
        for ip in list(user.ip_addresses):
            for rule in list(ip.access_rules):
                db.delete(rule)
            db.delete(ip)
        db.delete(user)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))


@app.route("/add_client_ip", methods=["POST"])
@admin_required
def add_client_ip():
    db = DbSession()
    ssh_username = request.form.get("ssh_username", "").strip() or None
    ssh_password = request.form.get("ssh_password")
    ssh_key_path = request.form.get("ssh_key_path", "").strip() or None
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
    db = DbSession()
    ip = db.get(ClientIP, ip_id)
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
    db = DbSession()
    rule = db.get(ServerAccessRule, rule_id)
    if rule:
        db.delete(rule)
        db.commit()
    db.close()
    return redirect(url_for("dashboard"))

@app.route("/logs")
@login_required
def logs():
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
    db = DbSession()
    settings = db.query(AppSettings).first()
    port = settings.web_ui_port if settings else 8080
    db.close()
    app.run(host="0.0.0.0", port=port, debug=True)
