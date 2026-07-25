import socket
import threading
import paramiko

# Параметры удалённого SSH-сервера (T14)
SSH_HOST = "10.87.151.206"
SSH_PORT = 22
SSH_USERNAME = "T14"
SSH_PASSWORD = "170695"
SUBSYSTEM_NAME = "echo"

# Параметры локального TCP-порта, на который будет подключаться "клиент"
LOCAL_HOST = "0.0.0.0"
LOCAL_PORT = 15001


def forward_client_to_channel(client_sock, channel):
    """Копирует байты из TCP-сокета клиента в SSH-канал."""
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
    """Копирует байты из SSH-канала обратно в TCP-сокет клиента."""
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


def handle_client(client_sock, addr):
    print(f"[+] Новое подключение от {addr}")

    ssh_client = paramiko.SSHClient()
    ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    ssh_client.connect(
        SSH_HOST, port=SSH_PORT,
        username=SSH_USERNAME, password=SSH_PASSWORD,
        timeout=10,
    )

    transport = ssh_client.get_transport()
    channel = transport.open_session()
    channel.invoke_subsystem(SUBSYSTEM_NAME)

    # Запускаем два потока для одновременной перекачки в обе стороны
    t1 = threading.Thread(target=forward_client_to_channel, args=(client_sock, channel))
    t2 = threading.Thread(target=forward_channel_to_client, args=(channel, client_sock))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    ssh_client.close()
    print(f"[-] Соединение с {addr} закрыто")


def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((LOCAL_HOST, LOCAL_PORT))
    server_sock.listen(5)
    print(f"Слушаю TCP {LOCAL_HOST}:{LOCAL_PORT}, форвардю на subsystem '{SUBSYSTEM_NAME}' сервера {SSH_HOST}")

    while True:
        client_sock, addr = server_sock.accept()
        threading.Thread(target=handle_client, args=(client_sock, addr)).start()


if __name__ == "__main__":
    main()