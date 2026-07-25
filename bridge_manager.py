import socket
import threading
import paramiko
from models import Session, SSHServer, ClientIP, ServerAccessRule, AppSettings, RequestLog
from datetime import datetime
import os

class BridgeManager:
    def __init__(self):
        self.lock = threading.Lock()
        self.bridges = {}          # local_port -> {"rule":..., "server_sock":..., "sessions": {...}}
        self._next_session_id = 1

    # ---------- управление мостами (портами) ----------

    def start_bridge(self, rule):
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
        """Сравнивает базу с уже запущенными мостами: новые subsystem запускает, удалённые — останавливает."""
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
                        "subsystem": sub.name,
                        "server_id": server.id,
                        "server_name": server.name,
                    }
                    self.start_bridge(rule)
        session.close()

        removed_ports = set(self.bridges.keys()) - found_ports
        for port in removed_ports:
            print(f"Subsystem для порта {port} больше нет в базе, останавливаю мост.")
            self.stop_bridge(port)

    # ---------- приём подключений ----------

    def _accept_loop(self, local_port):
        bridge = self.bridges.get(local_port)
        server_sock = bridge["server_sock"]
        while True:
            try:
                client_sock, addr = server_sock.accept()
            except OSError:
                break  # сокет закрыт снаружи через stop_bridge()
            threading.Thread(target=self._handle_client, args=(client_sock, addr, local_port), daemon=True).start()

    def _handle_client(self, client_sock, addr, local_port):
        bridge = self.bridges.get(local_port)
        if bridge is None:
            client_sock.close()
            return
        rule = bridge["rule"]
        client_ip = addr[0]

        client_access = self._get_client_access(client_ip, rule["server_id"])
        if client_access is None:
            print(f"[!] [{local_port}] ОТКАЗ: {client_ip} не имеет доступа к {rule['server_name']}")
            client_sock.close()
            return

        ssh_username = client_access["ssh_username"] or rule["ssh_username"]
        ssh_password = client_access["ssh_password"]
        if ssh_password is None:
            ssh_password = rule["ssh_password"]
        ssh_key_path = client_access["ssh_key_path"]

        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        connect_kwargs = {
            "hostname": rule["ssh_host"],
            "port": rule["ssh_port"],
            "username": ssh_username,
            "timeout": 10,
            "allow_agent": False,
            "look_for_keys": False,
        }
        if ssh_key_path:
            connect_kwargs["key_filename"] = ssh_key_path
            if ssh_password:
                connect_kwargs["passphrase"] = ssh_password
        else:
            connect_kwargs["password"] = ssh_password or ""
        ssh_client.connect(**connect_kwargs)
        transport = ssh_client.get_transport()
        channel = transport.open_session()
        channel.invoke_subsystem(rule["subsystem"])
        log_id = self._log_connect(client_ip, rule)

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

        c2s_log, s2c_log = self._open_traffic_logs(session_id)  # НОВОЕ

        print(f"[+] [{local_port}] session #{session_id}: {client_ip} -> {rule['server_name']}:{rule['subsystem']}")

        t1 = threading.Thread(target=self._forward, args=(client_sock, channel, "c2s", c2s_log))
        t2 = threading.Thread(target=self._forward, args=(channel, client_sock, "s2c", s2c_log))
        t1.start();
        t2.start()
        t1.join();
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
        try:
            while True:
                data = src.recv(4096)
                if not data:
                    break
                if log_file:
                    log_file.write(data)
                if direction == "c2s":
                    dst.send(data)
                else:
                    dst.sendall(data)
        except (OSError, EOFError):
            pass
        finally:
            try:
                dst.close()
            except Exception:
                pass
            try:
                src.close()
            except Exception:
                pass

    def _get_client_access(self, client_ip, server_id):
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
    def _log_connect(client_ip, rule):
        db = Session()
        settings = db.query(AppSettings).first()
        if not settings or not settings.logging_enabled:
            db.close()
            return None
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
    def _open_traffic_logs(session_id):
        db = Session()
        settings = db.query(AppSettings).first()
        enabled = bool(settings and settings.logging_enabled)
        db.close()
        if not enabled:
            return None, None

        os.makedirs("logs", exist_ok=True)
        c2s_file = open(f"logs/session_{session_id}_c2s.bin", "ab")
        s2c_file = open(f"logs/session_{session_id}_s2c.bin", "ab")
        return c2s_file, s2c_file
    # ---------- управление сессиями (п.5, п.7 ТЗ) ----------

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
