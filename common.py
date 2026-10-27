import json
import socket
import threading

import aes


KEY_LENGTH = 16
MIN_PORT = 1
MAX_PORT = 65535


def log(label: str, message: str) -> None:
    print(f"[{label}] {message}")


def send(sock: socket.socket, obj: dict[str, object]) -> None:
    message = json.dumps(obj, separators=(",", ":"))
    sock.sendall(f"{message}\n".encode("utf-8"))


def recv(sock: socket.socket) -> dict[str, object]:
    buffer = bytearray()
    while True:
        chunk = sock.recv(1)
        if not chunk:
            if buffer:
                raise ValueError("Pesan jaringan tidak lengkap")
            raise ConnectionError("Koneksi ditutup")
        if chunk == b"\n":
            break
        buffer.extend(chunk)

    try:
        message = json.loads(buffer.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("Pesan JSON tidak valid") from error
    if not isinstance(message, dict):
        raise ValueError("Pesan JSON harus berupa object")
    return message


def seal(key: bytes, text: str) -> str:
    try:
        plaintext = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("Plaintext harus berupa ASCII") from error
    return aes.encrypt_cbc(key, plaintext).hex()


def unseal(key: bytes, hex_data: str) -> str:
    try:
        encrypted_data = bytes.fromhex(hex_data)
        plaintext = aes.decrypt_cbc(key, encrypted_data)
        return plaintext.decode("ascii")
    except (TypeError, ValueError, UnicodeDecodeError) as error:
        raise ValueError("Data terenkripsi tidak valid") from error


def valid_text(text: str) -> bool:
    return bool(text) and all(32 <= ord(char) <= 126 for char in text)


def ask_key(prompt: str) -> bytes:
    while True:
        value = input(prompt)
        if len(value) == KEY_LENGTH and valid_text(value):
            return value.encode("ascii")
        log("ERROR", "Key harus tepat 16 karakter ASCII printable.")


def parse_hostport(value: str) -> tuple[str, int]:
    host, separator, port_text = value.rpartition(":")
    if not separator or not host or not port_text:
        raise ValueError("Alamat harus berformat ip:port")
    try:
        port = int(port_text)
    except ValueError as error:
        raise ValueError("Port harus berupa angka") from error
    if port < MIN_PORT or port > MAX_PORT:
        raise ValueError("Port harus berada antara 1 dan 65535")
    return host, port


def run_menu(title: str, options: dict[str, tuple[str, object]]) -> None:
    while True:
        log(title, "")
        for choice, (label, _) in options.items():
            log(title, f"{choice}. {label}")
        log(title, "0. Keluar")
        choice = input("Pilihan: ").strip()
        if choice == "0":
            return
        selected = options.get(choice)
        if selected is None:
            log("ERROR", "Pilihan tidak valid.")
            continue
        action = selected[1]
        if not callable(action):
            raise TypeError("Aksi menu harus berupa fungsi")
        action()


def _receive_chat_messages(
    sock: socket.socket,
    session_key: bytes,
    chat_ended: threading.Event,
) -> None:
    while not chat_ended.is_set():
        try:
            message = recv(sock)
        except ConnectionError:
            if not chat_ended.is_set():
                log("CHAT", "Lawan memutus koneksi.")
                chat_ended.set()
            return
        except (OSError, ValueError):
            if not chat_ended.is_set():
                log("CHAT", "Pesan tidak valid.")
            continue

        if message.get("type") != "MSG":
            log("CHAT", "Pesan tidak valid.")
            continue
        encrypted_data = message.get("data")
        if not isinstance(encrypted_data, str):
            log("CHAT", "Pesan tidak valid.")
            continue
        try:
            text = unseal(session_key, encrypted_data)
        except ValueError:
            log("CHAT", "Pesan tidak valid.")
            continue
        log("TERIMA", f"{text} | Hex: {encrypted_data}")


def _close_socket(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except OSError:
        sock.close()
        return
    sock.close()


def chat_session(sock: socket.socket, session_key: bytes) -> None:
    chat_ended = threading.Event()
    receiver = threading.Thread(
        target=_receive_chat_messages,
        args=(sock, session_key, chat_ended),
        daemon=True,
    )
    receiver.start()

    try:
        while not chat_ended.is_set():
            try:
                text = input("Pesan (/exit untuk keluar): ")
            except EOFError:
                break
            if chat_ended.is_set():
                break
            if text == "/exit":
                break
            if not valid_text(text):
                log("ERROR", "Pesan tidak boleh kosong dan harus ASCII printable.")
                continue
            encrypted_data = seal(session_key, text)
            try:
                send(sock, {"type": "MSG", "data": encrypted_data})
            except OSError:
                log("CHAT", "Gagal mengirim pesan.")
                break
            log("KIRIM", f"{text} | Hex: {encrypted_data}")
    finally:
        chat_ended.set()
        _close_socket(sock)
        receiver.join()
