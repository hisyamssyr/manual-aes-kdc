import json
import secrets
import socket
import string
import threading
from pathlib import Path

import common


SESSION_KEY_CHARS = string.ascii_letters + string.digits


def _create_session_key() -> str:
    return "".join(secrets.choice(SESSION_KEY_CHARS) for _ in range(common.KEY_LENGTH))


def _handle_client(
    sock: socket.socket,
    addr: tuple[str, int],
    keys: dict[str, bytes],
    lock: threading.Lock,
) -> None:
    with sock:
        try:
            req = common.recv(sock)
            if req.get("type") != "REQ":
                return
            a = req.get("a")
            b = req.get("b")
            n1 = req.get("n1")
            if not isinstance(a, str) or not isinstance(b, str) or not isinstance(n1, int):
                raise ValueError("Format REQ tidak valid")

            with lock:
                ka = keys.get(a)
                kb = keys.get(b)
            if not ka or not kb:
                raise ValueError(f"Peserta tidak dikenal: {a} atau {b}")

            common.log("STEP 1", f"Permintaan {a} untuk {b} dari {addr[0]}:{addr[1]}.")
            ks = _create_session_key()
            for_a = common.seal(ka, f"{ks}|{a}|{b}|{n1}")
            ticket = common.seal(kb, f"{ks}|{a}")
            common.send(sock, {"type": "RESP", "for_a": for_a, "ticket": ticket})
            common.log("STEP 2", f"for_a={for_a}")
            common.log("STEP 2", f"ticket={ticket}")
        except Exception as error:
            common.log("ERROR", f"Permintaan ditolak: {error}")


def _serve(
    server_sock: socket.socket,
    stop: threading.Event,
    keys: dict[str, bytes],
    lock: threading.Lock,
) -> None:
    while not stop.is_set():
        try:
            conn, addr = server_sock.accept()
            threading.Thread(
                target=_handle_client,
                args=(conn, addr, keys, lock),
                daemon=True,
            ).start()
        except OSError:
            break


def _change_key(keys: dict[str, bytes], lock: threading.Lock, user: str) -> None:
    key = common.ask_key(f"Key {user}: ")
    with lock:
        keys[user] = key
    common.log("KEY", f"Key {user} berhasil diubah.")


def main() -> None:
    with open("config.json", encoding="utf-8") as config_file:
        settings = json.load(config_file)
    kdc_config = settings["kdc"]
    bind_host = kdc_config.get("bind_host", "0.0.0.0")
    port = kdc_config["port"]
    log_path = Path(__file__).resolve().parent / "log" / "kdc.log"
    common.configure_logging(log_path, console=False)

    keys = {
        "alice": common.ask_key("Key Alice: "),
        "bob": common.ask_key("Key Bob: "),
    }
    lock = threading.Lock()
    stop = threading.Event()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.settimeout(0.5)
    server.bind((bind_host, port))
    server.listen()

    thread = threading.Thread(
        target=_serve, args=(server, stop, keys, lock), daemon=True
    )
    thread.start()
    common.log("KDC", f"Server berjalan di {bind_host}:{port}.")

    try:
        common.run_menu("KDC", {
            "1": ("Ubah key Alice", lambda: _change_key(keys, lock, "alice")),
            "2": ("Ubah key Bob", lambda: _change_key(keys, lock, "bob")),
        })
    except KeyboardInterrupt:
        common._console_log("KDC", "Server dihentikan.")
    finally:
        stop.set()
        server.close()
        thread.join(timeout=1.0)
        common.close_logging()


if __name__ == "__main__":
    main()
