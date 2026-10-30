import json
import socket
import threading
from pathlib import Path

import aes


KEY_LENGTH = 16
_CONSOLE_LOCK = threading.Lock()
_LOG_LOCK = threading.Lock()
_LOG_FILE = None
_LOG_TO_CONSOLE = True


def configure_logging(path: str | Path | None = None, console: bool = True) -> None:
    """Configure an optional log file and whether logs are echoed to the terminal."""
    global _LOG_FILE, _LOG_TO_CONSOLE
    with _LOG_LOCK:
        if _LOG_FILE is not None:
            _LOG_FILE.close()
            _LOG_FILE = None
        if path is not None:
            log_path = Path(path)
            log_path.parent.mkdir(parents=True, exist_ok=True)
            _LOG_FILE = log_path.open("a", encoding="utf-8", buffering=1)
        _LOG_TO_CONSOLE = console


def close_logging() -> None:
    """Close the configured log file."""
    global _LOG_FILE, _LOG_TO_CONSOLE
    with _LOG_LOCK:
        if _LOG_FILE is not None:
            _LOG_FILE.close()
            _LOG_FILE = None
        _LOG_TO_CONSOLE = True


def _console_log(label: str, message: str) -> None:
    with _CONSOLE_LOCK:
        print(f"[{label}] {message}", flush=True)


def log(label: str, message: str) -> None:
    line = f"[{label}] {message}"
    with _LOG_LOCK:
        if _LOG_FILE is not None:
            _LOG_FILE.write(line + "\n")
            _LOG_FILE.flush()
        if _LOG_TO_CONSOLE:
            with _CONSOLE_LOCK:
                print(line, flush=True)


def _read_input(prompt: str) -> str:
    """Read terminal input while allowing background receive logs to appear."""
    return input(prompt)


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
        val = _read_input(prompt).strip()
        if len(val) == KEY_LENGTH and valid_text(val):
            return val.encode("ascii")
        _console_log("ERROR", "Key harus tepat 16 karakter ASCII printable.")


def run_menu(title: str, options: dict[str, tuple[str, object]]) -> None:
    while True:
        _console_log(title, "")
        for k, (lbl, _) in options.items():
            _console_log(title, f"{k}. {lbl}")
        _console_log(title, "0. Keluar")
        choice = _read_input("Pilihan: ").strip()
        if choice == "0":
            return
        selected = options.get(choice)
        if selected:
            selected[1]()
        else:
            _console_log("ERROR", "Pilihan tidak valid.")


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
                text = _read_input("Pesan (/exit untuk keluar): ")
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
