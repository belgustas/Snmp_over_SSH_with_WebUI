"""
SSH-мосты (туннели): localhost:9999 ↔ SSH-server:22 ↔ subsystem (e.g. snmp).

Этот модуль запускает локальные портыи перенаправляет трафик на удалённые SSH-серверы.
Каждое подключение проверяется по правилам доступа, логируется и может быть разорвано админом.

Два главных потока на сокет подключение:
  - t1: клиент → SSH-канал
  - t2: SSH-канал → клиент
"""

import socket
import threading
import paramiko
from models import Session, SSHServer, ClientIP, ServerAccessRule, AppSettings, RequestLog
from datetime import datetime
import os
import traceback  # добавь в начало файла, если ещё нет


class BridgeManager:
    # Управляет всеми туннелями (мостами) между локальными портами и удалёнными серверами

    def __init__(self):
        self.lock = threading.Lock()
        # self.bridges[local_port] = {rule, server_sock, sessions}
        # где sessions[session_id] = {client_sock, channel, ssh_client, client_ip, ...}
        self.bridges = {}
        self._next_session_id = 1

    # Запуск и остановка мостов

    def start_bridge(self, rule):
        # Запускаем мост: открываем локальный порт и ждём входящих подключений в отдельном потоке
        with self.lock:
            if rule["local_port"] in self.bridges:
                print(f"Порт {rule['local_port']} уже занят мостом, пропускаю.")
                return
            server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_sock.bind(("0.0.0.0", rule["local_port"]))
            server_sock.listen(5)
            self.bridges[rule["local_port"]] = {
                "rule": rule,
                "server_sock": server_sock,
                "sessions": {},
            }
        threading.Thread(target=self._accept_loop, args=(rule["local_port"],), daemon=True).start()
        print(f"[+] Мост запущен: порт {rule['local_port']} -> {rule['server_name']}:{rule['subsystem']}")

    def stop_bridge(self, local_port):
        # Закрываем мост: сокет (это выведет _accept_loop), затем разорваём все сессии
        with self.lock:
            bridge = self.bridges.pop(local_port, None)
        if not bridge:
            print(f"Моста на порту {local_port} нет.")
            return
        bridge["server_sock"].close()
        for session_id in list(bridge["sessions"].keys()):
            self._close_session(bridge, session_id)
        print(f"[-] Мост на порту {local_port} остановлен.")

    def reload_from_db(self):
        # Сравниваем БД с запущенными мостами:
        # - Если в БД есть новый subsystem → запускаем мост
        # - Если мост есть в памяти, но его нет в БД → закрываем мост
        # Это позволяет апдейтить конфиг БД, вызвать reload_from_db() и не перезагружать приложение

        session = Session()
        found_ports = set()

        for server in session.query(SSHServer).all():
            for sub in server.subsystems:
                found_ports.add(sub.local_port)
                if sub.local_port not in self.bridges:
                    rule = {
                        "local_port": sub.local_port,
                        "ssh_host": server.host,
                        "ssh_port": server.port,
                        "ssh_username": server.proxy_username,
                        "ssh_password": server.proxy_password,
                        "ssh_key_path": server.proxy_key_path,
                        "subsystem": sub.name,
                        "server_id": server.id,
                        "server_name": server.name,
                    }
                    self.start_bridge(rule)
        session.close()

        # Ищем "мёртвые" мосты (есть в памяти, нет в БД) и закрываем их
        removed_ports = set(self.bridges.keys()) - found_ports
        for port in removed_ports:
            print(f"Subsystem для порта {port} больше нет в базе, останавливаю мост.")
            self.stop_bridge(port)

    # Поиск подключений

    def _accept_loop(self, local_port):
        # Главный цикл для этого порта: слушаем входящие подключения в отдельном потоке
        # Для каждого клиента запускаем новый поток _handle_client
        bridge = self.bridges.get(local_port)
        server_sock = bridge["server_sock"]
        while True:
            try:
                client_sock, addr = server_sock.accept()
            except OSError:
                # Сокет закрыт из stop_bridge() → выходим из цикла
                break
            threading.Thread(target=self._handle_client, args=(client_sock, addr, local_port), daemon=True).start()

    def _handle_client(self, client_sock, addr, local_port):

        # Вся логика для одного подключения:
        # 1. Проверяем доступ (IP в разрешённых для этого сервера?)
        # 2. Подключаемся к SSH-серверу со своими учётками
        # 3. Открываем subsystem на сервере
        # 4. Логируем подключение в БД
        # 5. Запускаем два потока для двусторонней передачи данных
        # 6. Когда подключение закончится — логируем отключение

        bridge = self.bridges.get(local_port)
        if bridge is None:
            client_sock.close()
            return
        rule = bridge["rule"]
        client_ip = addr[0]

        access = self._get_client_access(client_ip, rule["server_id"])
        if access is None:
            print(f"[!] [{local_port}] ОТКАЗ: {client_ip} не имеет доступа к {rule['server_name']}")
            client_sock.close()
            return

        # Если для этого IP заданы персональные SSH-учётки — используем их,
        # иначе берём общие учётки сервера (proxy_username/proxy_password/proxy_key_path).
        ssh_username = access["ssh_username"] or rule["ssh_username"]
        ssh_password = access["ssh_password"] or rule["ssh_password"]
        ssh_key_path = access["ssh_key_path"] or rule.get("ssh_key_path")

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        connect_kwargs = {
            "hostname": rule["ssh_host"],
            "port": rule["ssh_port"],
            "username": ssh_username,
            "timeout": 10,
        }
        if ssh_key_path:
            connect_kwargs["key_filename"] = ssh_key_path
            if ssh_password:
                connect_kwargs["passphrase"] = ssh_password
        else:
            connect_kwargs["password"] = ssh_password or ""

        try:
            ssh_client.connect(**connect_kwargs)
            transport = ssh_client.get_transport()
            channel = transport.open_session()
            channel.invoke_subsystem(rule["subsystem"])
        except Exception:
            print(f"[!] [{local_port}] Не удалось установить SSH/subsystem для {client_ip}:")
            traceback.print_exc()
            try:
                ssh_client.close()
            except Exception:
                pass
            client_sock.close()
            return
        logging_enabled = self._get_logging_enabled()

        log_id = self._log_connect(client_ip, rule, logging_enabled)

        with self.lock:
            session_id = self._next_session_id
            self._next_session_id += 1
            bridge["sessions"][session_id] = {
                "client_sock": client_sock,
                "channel": channel,
                "ssh_client": ssh_client,
                "client_ip": client_ip,
                "ssh_username": ssh_username,
                "rule": rule,
                "log_id": log_id,
            }

        c2s_log, s2c_log = self._open_traffic_logs(log_id, logging_enabled)

        print(f"[+] [{local_port}] session #{session_id}: {client_ip} -> {rule['server_name']}:{rule['subsystem']}")

        t1 = threading.Thread(target=self._forward, args=(client_sock, channel, "c2s", c2s_log))
        t2 = threading.Thread(target=self._forward, args=(channel, client_sock, "s2c", s2c_log))
        t1.start()
        t2.start()
        t1.join()
        t2.join()

        if c2s_log:
            c2s_log.close()
        if s2c_log:
            s2c_log.close()

        with self.lock:
            bridge["sessions"].pop(session_id, None)
        ssh_client.close()
        self._log_disconnect(log_id)
        print(f"[-] [{local_port}] session #{session_id} закрыта")

    @staticmethod
    def _forward(src, dst, direction, log_file=None):
        # Двусторонняя трубка: читаем из src (4KB за раз), пишем в dst
        # direction нужен только для выбора send vs sendall (optimization)
        # Если есть log_file — пишем туда копию трафика (для аудита)
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    # Одна сторона разорвала соединение → завершаемся
                    break
                if log_file:
                    log_file.write(data)  # логируем трафик в файл
                if direction == "c2s":
                    dst.send(data)
                else:
                    dst.sendall(data)  # sendall гарантирует, что всё отправится
        except (OSError, EOFError):
            # Ошибка сокета — это нормально при разрыве соединения
            pass
        finally:
            # КРИТИЧНО: закрываем оба сокета в любом случае, иначе зависнут соединения
            try:
                dst.close()
            except Exception:
                pass
            try:
                src.close()
            except Exception:
                pass

    def _get_client_access(self, client_ip, server_id):
        # Ищем в БД: этот IP есть в разрешённых для этого сервера?
        # Если да И пользователь не истёк → возвращаем его SSH-учётки
        # Если нет → None (отказ в доступе)

        session = Session()
        rule = (
            session.query(ServerAccessRule)
            .join(ClientIP)
            .filter(ClientIP.ip_address == client_ip, ServerAccessRule.server_id == server_id)
            .first()
        )
        result = None
        if rule and not rule.client_ip.user.is_expired():
            result = {
                "ssh_username": rule.client_ip.ssh_username,
                "ssh_password": rule.client_ip.ssh_password,
                "ssh_key_path": rule.client_ip.ssh_key_path,
            }
        session.close()
        return result

    @staticmethod
    def _get_logging_enabled():
        """
        Читает флаг logging_enabled из AppSettings РОВНО ОДИН РАЗ за подключение.
        Раньше этот же запрос дублировался и в _log_connect(), и в
        _open_traffic_logs() — двумя отдельными обращениями к БД в разные
        моменты времени, из-за чего решение "логировать или нет" могло
        отличаться для записи в БД и для файлов трафика одной и той же сессии.
        """
        db = Session()
        settings = db.query(AppSettings).first()
        enabled = bool(settings and settings.logging_enabled)
        db.close()
        return enabled

    @staticmethod
    def _log_connect(client_ip, rule, logging_enabled):
        """
        Логирует подключение клиента в БД (таблица RequestLog).

        Действия:
          1. Принимаем уже готовый флаг logging_enabled (см. _get_logging_enabled)
          2. Создаём запись RequestLog с временем подключения
          3. Возвращаем ID записи (нужен для последующего _log_disconnect
             и для имени файлов трафика)

        Возвращает:
          - ID записи (если логирование включено)
          - None (если логирование отключено)
        """
        if not logging_enabled:
            return None
        db = Session()
        # Создаём запись о подключении
        entry = RequestLog(
            client_ip=client_ip,
            server_name=rule["server_name"],
            subsystem_name=rule["subsystem"],
            local_port=rule["local_port"],
            connected_at=datetime.utcnow(),
        )
        db.add(entry)
        db.commit()
        log_id = entry.id
        db.close()
        return log_id

    @staticmethod
    def _log_disconnect(log_id):
        if log_id is None:
            return
        db = Session()
        entry = db.get(RequestLog, log_id)
        if entry:
            entry.disconnected_at = datetime.utcnow()
            db.commit()
        db.close()

    @staticmethod
    def _open_traffic_logs(log_id, logging_enabled):
        """
        Открывает два файла для логирования трафика (если логирование включено).

        Файлы называются по log_id — это ID записи в таблице RequestLog
        (постоянный, никогда не повторяется, переживает перезапуск приложения).
        Раньше файлы назывались по session_id, который живёт только в памяти
        процесса и обнуляется до 1 при каждом перезапуске — из-за этого
        трафик разных, не связанных друг с другом подключений мог дописываться
        (режим "ab") в один и тот же файл.

        Файлы:
          - logs/log_{log_id}_c2s.bin: трафик от клиента к серверу
          - logs/log_{log_id}_s2c.bin: трафик от сервера к клиенту

        Возвращает:
          - (c2s_file, s2c_file) если логирование включено
          - (None, None) если логирование отключено или log_id отсутствует
        """
        if not logging_enabled or log_id is None:
            return None, None

        # Создаём директорию logs, если её нет
        os.makedirs("logs", exist_ok=True)
        # Открываем файлы в режиме append-binary
        c2s_file = open(f"logs/log_{log_id}_c2s.bin", "ab")
        s2c_file = open(f"logs/log_{log_id}_s2c.bin", "ab")
        return c2s_file, s2c_file

    def list_sessions(self):
        result = []
        with self.lock:
            for port, bridge in self.bridges.items():
                for session_id, info in bridge["sessions"].items():
                    result.append((
                        session_id,
                        port,
                        info["client_ip"],
                        info["ssh_username"],
                        info["rule"]["server_name"],
                        info["rule"]["subsystem"],
                    ))
        return result

    def disconnect_session(self, session_id):
        with self.lock:
            for port, bridge in self.bridges.items():
                if session_id in bridge["sessions"]:
                    self._close_session(bridge, session_id)
                    return True
        return False

    def _close_session(self, bridge, session_id):
        # Закрываем оба конца туннеля (это вызовет выход из обоих _forward потоков)
        info = bridge["sessions"].get(session_id)
        if not info:
            return
        try:
            info["channel"].close()
        except Exception:
            pass
        try:
            info["client_sock"].close()
        except Exception:
            pass