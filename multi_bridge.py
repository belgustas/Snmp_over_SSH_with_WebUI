import socket
import threading
import paramiko


# Список правил: каждое правило описывает один "мост"
BRIDGES = [
    {
        "local_port": 15001,
        "ssh_host": "10.87.151.206",
        "ssh_port": 22,
        "ssh_username": "T14",
        "ssh_password": "170695",
        "subsystem": "echo",
    },
    # Сюда позже можно добавить ещё правила, например:
    {
        "local_port": 15002,
        "ssh_host": "10.87.151.206",
        "ssh_port": 22,
        "ssh_username": "T14",
        "ssh_password": "170695",
        "subsystem": "echo2",
    },
]


def forward_client_to_channel(client_sock, channel):
    try:
        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            channel.send(data)
    except (OSError, EOFError):
        pass
    finally:
        channel.close()


def forward_channel_to_client(channel, client_sock):
    try:
        while True:
            data = channel.recv(4096)
            if not data:
                break
            client_sock.sendall(data)
    except (OSError, EOFError):
        pass
    finally:
        client_sock.close()


def handle_client(client_sock, addr, rule):
    print(f"[+] [{rule['local_port']}] Новое подключение от {addr} -> {rule['ssh_host']}:{rule['subsystem']}")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        rule["ssh_host"], port=rule["ssh_port"],
        username=rule["ssh_username"], password=rule["ssh_password"],
        timeout=10,
    )

    transport = ssh_client.get_transport()
    channel = transport.open_session()
    channel.invoke_subsystem(rule["subsystem"])

    t1 = threading.Thread(target=forward_client_to_channel, args=(client_sock, channel))
    t2 = threading.Thread(target=forward_channel_to_client, args=(channel, client_sock))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    ssh_client.close()
    print(f"[-] [{rule['local_port']}] Соединение с {addr} закрыто")


def run_bridge_server(rule):
    """Поднимает один TCP-сервер для одного правила (одного порта)."""
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("0.0.0.0", rule["local_port"]))
    server_sock.listen(5)
    print(f"Слушаю TCP 0.0.0.0:{rule['local_port']} -> {rule['ssh_host']}:{rule['subsystem']}")

    while True:
        client_sock, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr, rule)).start()


def main():
    threads = []
    for rule in BRIDGES:
        t = threading.Thread(target=run_bridge_server, args=(rule,), daemon=True)
        t.start()
        threads.append(t)

    print(f"Запущено мостов: {len(threads)}. Нажмите Ctrl+C для остановки.")
    for t in threads:
        t.join()


if __name__ == "__main__":
    main()
