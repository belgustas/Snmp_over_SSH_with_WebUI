from models import Session, SSHServer, ClientIP, AppSettings
from models import User

session = Session()


for server in session.query(SSHServer).all():
    print(f"Сервер: {server.name} ({server.host}:{server.port})")
    for sub in server.subsystems:
        print(f"  -> subsystem '{sub.name}' на локальном порту {sub.local_port}")

print("\nПользователи:")
for user in session.query(User).all():
    print(f"  {user.username} (группа: {user.group.name})")

print("\nПрава доступа:")
for ip in session.query(ClientIP).all():
    print(f"IP {ip.ip_address} (пользователь: {ip.user.username}):")
    for rule in ip.access_rules:
        print(f"  -> доступ к серверу {rule.server.name}")

print("\nНастройки приложения:")
settings = session.query(AppSettings).first()
print(f"  Название: {settings.app_name}")
print(f"  Логирование включено: {settings.logging_enabled}")
print(f"  Порт Web UI: {settings.web_ui_port}")

print("\nПроверка срока действия учёток:")
for user in session.query(User).all():
    status = "ИСТЕКЛА" if user.is_expired() else "активна"
    print(f"  {user.username}: {status}")
session.close()