import socket


with socket.create_connection(("127.0.0.1", 15001), timeout=5) as s:
    s.sendall(b"hello\n")
    print(s.recv(1024))
    try:
        s.shutdown(socket.SHUT_RDWR)
    except OSError:
        pass
