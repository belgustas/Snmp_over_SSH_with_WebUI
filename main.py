from bridge_manager import BridgeManager


def main():
    manager = BridgeManager()
    manager.reload_from_db()

    print("Команды: reload | list | kill <id> | quit")
    while True:
        cmd = input("> ").strip()
        if cmd == "quit":
            break
        elif cmd == "reload":
            manager.reload_from_db()
        elif cmd == "list":
            sessions = manager.list_sessions()
            if not sessions:
                print("Активных сессий нет.")
            for session_id, port, ip, ssh_username, server_name, subsystem in sessions:
                print(f"  #{session_id}  порт {port}  {ip} as {ssh_username} -> {server_name}:{subsystem}")
        elif cmd.startswith("kill "):
            session_id = int(cmd.split()[1])
            ok = manager.disconnect_session(session_id)
            print("Сессия отключена." if ok else "Такой сессии нет.")
        else:
            print("Неизвестная команда.")


if __name__ == "__main__":
    main()
