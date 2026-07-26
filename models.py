from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, DateTime, Boolean, text
from sqlalchemy.orm import declarative_base, relationship, sessionmaker
from datetime import datetime

Base = declarative_base()


class SSHServer(Base):
    # SSH-сервер (например, какой-то T14, роутер, коммутатор)
    # На этом сервере вешаются subsystems (snmp, netconf, etc)
    __tablename__ = "ssh_servers"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=22)
    proxy_username = Column(String, nullable=False)  # учётки прокси для подключения к серверу
    proxy_password = Column(String, nullable=False)

    subsystems = relationship("Subsystem", back_populates="server")
    access_rules = relationship("ServerAccessRule", back_populates="server")


class Subsystem(Base):
    # Subsystem на сервере (snmp, netconf, etc) + какой локальный порт его открыть
    # Пример: localhost:9999 открывает snmp на T14
    __tablename__ = "subsystems"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    local_port = Column(Integer, nullable=False, unique=True)  # юникально, не может быть две подсистемы на одном порту
    server_id = Column(Integer, ForeignKey("ssh_servers.id"), nullable=False)

    server = relationship("SSHServer", back_populates="subsystems")


class Group(Base):
    # Группа для RBAC (admin, operator, etc)
    __tablename__ = "groups"

    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False, unique=True)

    users = relationship("User", back_populates="group")


class User(Base):
    # Юзер ПРИЛОЖЕНИЯ (not SSH-юзер на сервере!)
    # Пароль хэшируется bcrypt'ом
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String, nullable=False, unique=True)
    password_hash = Column(String, nullable=False)
    group_id = Column(Integer, ForeignKey("groups.id"), nullable=False)
    expires_at = Column(DateTime, nullable=True)  # None = никогда не истекает

    group = relationship("Group", back_populates="users")
    ip_addresses = relationship("ClientIP", back_populates="user")

    def is_expired(self) -> bool:
        # Проверяем, прошла ли дата истечения (если она задана)
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at


class ClientIP(Base):
    # IP-адрес, с которого может подключаться юзер
    # Опционально: со своими SSH-учётками для подключения к серверам
    __tablename__ = "client_ips"

    id = Column(Integer, primary_key=True)
    ip_address = Column(String, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    ssh_username = Column(String, nullable=True)  # если None → используются учётки сервера
    ssh_password = Column(String, nullable=True)
    ssh_key_path = Column(String, nullable=True)

    user = relationship("User", back_populates="ip_addresses")
    access_rules = relationship("ServerAccessRule", back_populates="client_ip")


class ServerAccessRule(Base):
    # "IP X может подключиться к серверу Y через этот прокси"
    # Это та самая таблица, где проверяется доступ в _get_client_access()
    __tablename__ = "server_access_rules"

    id = Column(Integer, primary_key=True)
    client_ip_id = Column(Integer, ForeignKey("client_ips.id"), nullable=False)
    server_id = Column(Integer, ForeignKey("ssh_servers.id"), nullable=False)

    client_ip = relationship("ClientIP", back_populates="access_rules")
    server = relationship("SSHServer", back_populates="access_rules")


class AppSettings(Base):
    # Глобальные настройки (название app, логирование, порт)
    # Ожидаем ровно ОДНУ строку в этой таблице (ID=1)
    __tablename__ = "app_settings"

    id = Column(Integer, primary_key=True)
    app_name = Column(String, nullable=False, default="SSH Subsystem Proxy")
    logging_enabled = Column(Boolean, nullable=False, default=True)
    web_ui_port = Column(Integer, nullable=False, default=8080)


class RequestLog(Base):
    # История подключений (audit log)
    # Заполняется в _log_connect() когда клиент подключается
    # И завершается в _log_disconnect() когда отключается
    __tablename__ = "request_logs"

    id = Column(Integer, primary_key=True)
    client_ip = Column(String, nullable=False)
    server_name = Column(String, nullable=False)
    subsystem_name = Column(String, nullable=False)
    local_port = Column(Integer, nullable=False)
    connected_at = Column(DateTime, nullable=False)
    disconnected_at = Column(DateTime, nullable=True)  # заполняется при отключении


# ========== ИНИЦИАЛИЗАЦИЯ БД ==========
engine = create_engine("sqlite:///proxy.db")
Base.metadata.create_all(engine)  # создаём таблицы, если их нет


def migrate_existing_sqlite_schema():
    # Миграция для старых БД (если был апгрейд — добавляем новые колонки без потери данных)
    # Это нужно потому что SQLite не поддерживает ALTER в полной мере
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

# Глобальный sessionmaker (используется везде как DbSession() в app.py)
Session = sessionmaker(bind=engine)
