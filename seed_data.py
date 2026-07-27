from models import Session, SSHServer, Subsystem, Group, User, ClientIP, ServerAccessRule, AppSettings
from auth_utils import hash_password

session = Session()

server = session.query(SSHServer).filter_by(host="10.87.151.206").first()

if not server:
    server = SSHServer(
        name="T14",
        host="10.87.151.206",
        port=22,
        proxy_username="T14",
        proxy_password="170695",
    )
    session.add(server)
    session.commit()  # нужно сохранить, чтобы у server появился id

    subsystem1 = Subsystem(name="echo", local_port=15001, server_id=server.id)
    subsystem2 = Subsystem(name="echo2", local_port=15002, server_id=server.id)
    session.add_all([subsystem1, subsystem2])
    session.commit()

    print("Данные добавлены.")
else:
    print("Сервер уже существует, пропускаю.")

# Группы
admin_group = session.query(Group).filter_by(name="admin").first()
if not admin_group:
    admin_group = Group(name="admin")
    session.add(admin_group)

operator_group = session.query(Group).filter_by(name="operator").first()
if not operator_group:
    operator_group = Group(name="operator")
    session.add(operator_group)

session.commit()

# Пользователь-администратор
admin_user = session.query(User).filter_by(username="admin").first()
if not admin_user:
    admin_user = User(
        username="admin",
        password_hash=hash_password("admin123"),  # смените на нормальный пароль
        group_id=admin_group.id,
    )
    session.add(admin_user)
    session.commit()
    print("Пользователь admin создан.")
else:
    print("Пользователь admin уже существует, пропускаю.")

# Разрешим самому admin обращаться с localhost к серверу T14
existing_ip = session.query(ClientIP).filter_by(ip_address="127.0.0.1").first()
if not existing_ip:
    admin_ip = ClientIP(
        ip_address="127.0.0.1",
        user_id=admin_user.id,
        ssh_username=server.proxy_username,
        ssh_password=server.proxy_password,
    )
    session.add(admin_ip)
    session.commit()

    rule = ServerAccessRule(client_ip_id=admin_ip.id, server_id=server.id)
    session.add(rule)
    session.commit()
    print("Право доступа добавлено.")
else:
    print("IP уже существует, пропускаю.")

# Настройки приложения — создаём ровно одну запись, если её ещё нет
existing_settings = session.query(AppSettings).first()
if not existing_settings:
    settings = AppSettings()  # используются значения по умолчанию из models.py
    session.add(settings)
    session.commit()
    print("Настройки приложения созданы.")
else:
    print("Настройки уже существуют, пропускаю.")
session.close()
