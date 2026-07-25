import paramiko

HOST = "10.87.151.206"
PORT = 22
USERNAME = "T14"
PASSWORD = "170695"   # замените на реальный

# Шаг 1: обычное SSH-подключение (это вы уже делали в tunnel.py)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
client.connect(HOST, port=PORT, username=USERNAME, password=PASSWORD)

transport = client.get_transport()

# Шаг 2: открыть session-канал
channel = transport.open_session()

# Шаг 3: превратить его в subsystem-канал
channel.invoke_subsystem("echo")

# Шаг 4: отправить данные и прочитать эхо-ответ
message = b"Hello, subsystem!\n"
channel.send(message)

response = channel.recv(1024)
print("Получено обратно:", response)

channel.close()
client.close()