from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime

Base = declarative_base()


class SSHServer(Base):
    """Один SSH-сервер, к которому прокси может подключаться (например, T14)."""
    __tablename__ = "ssh_servers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=22)
    proxy_username = Column(String, nullable=False)
    proxy_password = Column(String, nullable=False)

    subsystems = relationship("Subsystem", back_populates="server")
    access_rules = relationship("ServerAccessRule", back_populates="server")   # НОВОЕ


class Subsystem(Base):
    """Один subsystem на конкретном сервере + локальный порт для доступа к нему."""
    __tablename__ = "subsystems"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    local_port = Column(Integer, nullable=False, unique=True)
    server_id = Column(Integer, ForeignKey("ssh_servers.id"), nullable=False)

    server = relationship("SSHServer", back_populates="subsystems")


class Group(Base):
    """Группа пользователей прокси: admin или operator."""
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)

    users = relationship("User", back_populates="group")


class User(Base):
    """Пользователь самого приложения-прокси (не путать с пользователем SSH-сервера)."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    expires_at = Column(DateTime, nullable=True)  # None означает "бессрочно"

    group = relationship("Group", back_populates="users")

    def is_expired(self) -> bool:
        """Проверяет, истёк ли срок действия учётки. Если expires_at не задан — учётка бессрочна."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at

    ip_addresses = relationship("ClientIP", back_populates="user")   # НОВОЕ


class ClientIP(Base):                                                # НОВОЕ
    """IP-адрес, с которого пользователю разрешено обращаться к прокси."""
    __tablename__ = "client_ips"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ssh_username = Column(String, nullable=True)
    ssh_password = Column(String, nullable=True)
    ssh_key_path = Column(String, nullable=True)

    user = relationship("User", back_populates="ip_addresses")
    access_rules = relationship("ServerAccessRule", back_populates="client_ip")


class ServerAccessRule(Base):                                        # НОВОЕ
    """Правило доступа: этому IP-адресу разрешено обращаться к этому SSH-серверу."""
    __tablename__ = "server_access_rules"

    id = Column(Integer, primary_key=True)
    client_ip_id = Column(Integer, ForeignKey("client_ips.id"), nullable=False)
    server_id = Column(Integer, ForeignKey("ssh_servers.id"), nullable=False)

    client_ip = relationship("ClientIP", back_populates="access_rules")
    server = relationship("SSHServer", back_populates="access_rules")

class AppSettings(Base):
    """Настройки самого приложения — ожидается ровно одна строка в этой таблице."""
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)
    app_name = Column(String, nullable=False, default="SSH Subsystem Proxy")
    logging_enabled = Column(Boolean, nullable=False, default=True)
    web_ui_port = Column(Integer, nullable=False, default=8080)

class RequestLog(Base):
    """Запись о том, кто и когда подключался через прокси (п. 1, п. 8 ТЗ)."""
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True)
    client_ip = Column(String, nullable=False)
    server_name = Column(String, nullable=False)
    subsystem_name = Column(String, nullable=False)
    local_port = Column(Integer, nullable=False)
    connected_at = Column(DateTime, nullable=False)
    disconnected_at = Column(DateTime, nullable=True)

    
engine = create_engine("sqlite:///proxy.db")
Base.metadata.create_all(engine)


def migrate_existing_sqlite_schema():
    """Adds columns introduced after the initial SQLite schema was created."""
    with engine.begin() as connection:
        existing_columns = {
            row[1]
            for row in connection.exec_driver_sql("PRAGMA table_info(client_ips)").fetchall()
        }
        if "ssh_username" not in existing_columns:
            connection.execute(text("ALTER TABLE client_ips ADD COLUMN ssh_username VARCHAR"))
        if "ssh_password" not in existing_columns:
            connection.execute(text("ALTER TABLE client_ips ADD COLUMN ssh_password VARCHAR"))
        if "ssh_key_path" not in existing_columns:
            connection.execute(text("ALTER TABLE client_ips ADD COLUMN ssh_key_path VARCHAR"))


migrate_existing_sqlite_schema()

Session = sessionmaker(bind=engine)
