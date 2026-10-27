import json
import socket
import threading

import aes


KEY_LENGTH = 16


def log(label: str, message: str) -> None:
    print(f"[{label}] {message}")


def send(sock: socket.socket, obj: dict[str, object]) -> None:
    message = json.dumps(obj, separators=(",", ":"))
    sock.sendall(f"{message}\n".encode("utf-8"))


def recv(sock: socket.socket) -> dict[str, object]:
    buf = bytearray()
    while True:
        b = sock.recv(1)
        if not b:
            if buf:
                raise ValueError("Pesan jaringan tidak lengkap")
            raise ConnectionError("Koneksi ditutup")
        if b == b"\n":
            break
        buf.extend(b)
    try:
        data = json.loads(buf.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Pesan JSON tidak valid") from error
    if not isinstance(data, dict):
        raise ValueError("Pesan harus berupa JSON object")
    return data


def seal(key: bytes, text: str) -> str:
    try:
        plaintext = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("Plaintext harus berupa ASCII") from error
    return aes.encrypt_cbc(key, plaintext).hex()


def unseal(key: bytes, hex_data: str) -> str:
    try:
        raw = bytes.fromhex(hex_data)
        return aes.decrypt_cbc(key, raw).decode("ascii")
    except Exception as error:
        raise ValueError("Data terenkripsi tidak valid") from error


def valid_text(text: str) -> bool:
    return bool(text) and all(32 <= ord(c) <= 126 for c in text)


def ask_key(prompt: str) -> bytes:
    while True:
        val = input(prompt).strip()
        if len(val) == KEY_LENGTH and valid_text(val):
            return val.encode("ascii")
        log("ERROR", "Key harus tepat 16 karakter ASCII printable.")


def parse_hostport(value: str) -> tuple[str, int]:
    host, sep, port_str = value.rpartition(":")
    if not sep or not host or not port_str:
        raise ValueError("Format harus ip:port")
    try:
        port = int(port_str)
        if not (1 <= port <= 65535):
            raise ValueError
        return host, port
    except ValueError:
        raise ValueError("Port harus berupa angka 1-65535")


def run_menu(title: str, options: dict[str, tuple[str, object]]) -> None:
    while True:
        log(title, "")
        for k, (lbl, _) in options.items():
            log(title, f"{k}. {lbl}")
        log(title, "0. Keluar")
        choice = input("Pilihan: ").strip()
        if choice == "0":
            return
        selected = options.get(choice)
        if selected:
            selected[1]()
        else:
            log("ERROR", "Pilihan tidak valid.")


def _recv_loop(
    sock: socket.socket, key: bytes, stop: threading.Event
) -> None:
    while not stop.is_set():
        try:
            msg = recv(sock)
        except Exception:
            if not stop.is_set():
                log("CHAT", "Lawan memutus koneksi.")
                stop.set()
            break
        if msg.get("type") == "MSG" and isinstance(msg.get("data"), str):
            try:
                text = unseal(key, msg["data"])
                log("TERIMA", f"{text} | Hex: {msg['data']}")
            except ValueError:
                log("CHAT", "Pesan rusak/tidak valid.")


def chat_session(sock: socket.socket, session_key: bytes) -> None:
    stop = threading.Event()
    receiver = threading.Thread(
        target=_recv_loop, args=(sock, session_key, stop), daemon=True
    )
    receiver.start()
    try:
        while not stop.is_set():
            try:
                text = input("Pesan (/exit untuk keluar): ")
            except (EOFError, KeyboardInterrupt):
                break
            if stop.is_set() or text == "/exit":
                break
            if not valid_text(text):
                log("ERROR", "Pesan harus ASCII printable dan tidak kosong.")
                continue
            enc = seal(session_key, text)
            try:
                send(sock, {"type": "MSG", "data": enc})
                log("KIRIM", f"{text} | Hex: {enc}")
            except OSError:
                log("CHAT", "Gagal mengirim pesan.")
                break
    finally:
        stop.set()
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        sock.close()
