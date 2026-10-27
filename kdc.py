import argparse
import secrets
import socket
import threading

import common


DEFAULT_KDC_PORT = 5000
SERVER_HOST = "0.0.0.0"
KEY_LENGTH = 16
MIN_NONCE = 1
MAX_NONCE = 2**32
SESSION_KEY_ALPHABET = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
)


def _create_session_key() -> str:
    return "".join(
        secrets.choice(SESSION_KEY_ALPHABET) for _ in range(KEY_LENGTH)
    )


def _parse_request(request: dict[str, object]) -> tuple[str, str, int]:
    if request.get("type") != "REQ":
        raise ValueError("Tipe pesan tidak valid")

    alice_id = request.get("a")
    bob_id = request.get("b")
    nonce = request.get("n1")
    if not isinstance(alice_id, str) or not isinstance(bob_id, str):
        raise ValueError("ID peserta tidak valid")
    if not isinstance(nonce, int) or isinstance(nonce, bool):
        raise ValueError("Nonce tidak valid")
    if nonce < MIN_NONCE or nonce > MAX_NONCE:
        raise ValueError("Nonce berada di luar batas")
    return alice_id, bob_id, nonce


def _get_participant_keys(
    key_store: dict[str, bytes],
    key_lock: object,
    alice_id: str,
    bob_id: str,
) -> tuple[bytes | None, bytes | None]:
    with key_lock:
        return key_store.get(alice_id), key_store.get(bob_id)


def _build_response(
    request: dict[str, object],
    key_store: dict[str, bytes],
    key_lock: object,
) -> tuple[str, str, str, str]:
    alice_id, bob_id, nonce = _parse_request(request)
    alice_key, bob_key = _get_participant_keys(
        key_store, key_lock, alice_id, bob_id
    )
    if alice_key is None or bob_key is None:
        raise ValueError(f"Peserta tidak dikenal: {alice_id} atau {bob_id}")

    session_key = _create_session_key()
    for_alice = common.seal(
        alice_key, f"{session_key}|{alice_id}|{bob_id}|{nonce}"
    )
    ticket = common.seal(bob_key, f"{session_key}|{alice_id}")
    return alice_id, bob_id, for_alice, ticket


def _handle_request(
    client_socket: socket.socket,
    address: tuple[str, int],
    key_store: dict[str, bytes],
    key_lock: object,
) -> None:
    try:
        request = common.recv(client_socket)
        alice_id, bob_id, for_alice, ticket = _build_response(
            request, key_store, key_lock
        )
        common.log(
            "STEP 1",
            f"Permintaan {alice_id} untuk {bob_id} dari {address[0]}:{address[1]}.",
        )
        common.send(
            client_socket,
            {"type": "RESP", "for_a": for_alice, "ticket": ticket},
        )
        common.log("STEP 2", f"for_a={for_alice}")
        common.log("STEP 2", f"ticket={ticket}")
    except (ConnectionError, OSError, TypeError, ValueError) as error:
        common.log("ERROR", f"Permintaan ditolak: {error}")


def _serve_requests(
    server_socket: socket.socket,
    stop_event: threading.Event,
    key_store: dict[str, bytes],
    key_lock: object,
) -> None:
    while not stop_event.is_set():
        try:
            client_socket, address = server_socket.accept()
        except OSError:
            if stop_event.is_set():
                return
            common.log("ERROR", "Gagal menerima koneksi.")
            continue

        handler = threading.Thread(
            target=_handle_connection,
            args=(client_socket, address, key_store, key_lock),
            daemon=True,
        )
        handler.start()


def _handle_connection(
    client_socket: socket.socket,
    address: tuple[str, int],
    key_store: dict[str, bytes],
    key_lock: object,
) -> None:
    with client_socket:
        _handle_request(client_socket, address, key_store, key_lock)


def _change_key(
    key_store: dict[str, bytes],
    key_lock: object,
    participant: str,
) -> None:
    key = common.ask_key(f"Key {participant}: ")
    with key_lock:
        key_store[participant] = key
    common.log("KEY", f"Key {participant} berhasil diubah.")


def _create_server_socket(port: int) -> socket.socket:
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((SERVER_HOST, port))
    server_socket.listen()
    return server_socket


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_KDC_PORT,
        help=f"Port KDC (default: {DEFAULT_KDC_PORT})",
    )
    return parser.parse_args()


def _create_key_store() -> dict[str, bytes]:
    return {
        "alice": common.ask_key("Key Alice: "),
        "bob": common.ask_key("Key Bob: "),
    }


def _run_kdc_menu(key_store: dict[str, bytes], key_lock: object) -> None:
    def change_alice_key() -> None:
        _change_key(key_store, key_lock, "alice")

    def change_bob_key() -> None:
        _change_key(key_store, key_lock, "bob")

    menu_options = {
        "1": ("Ubah key Alice", change_alice_key),
        "2": ("Ubah key Bob", change_bob_key),
    }
    common.run_menu("KDC", menu_options)


def _run_server(
    port: int,
    key_store: dict[str, bytes],
    key_lock: object,
) -> None:
    stop_event = threading.Event()

    try:
        server_socket = _create_server_socket(port)
    except OSError as error:
        common.log("ERROR", f"KDC tidak dapat berjalan: {error}")
        return

    server_thread = threading.Thread(
        target=_serve_requests,
        args=(server_socket, stop_event, key_store, key_lock),
        daemon=True,
    )
    server_thread.start()
    common.log("KDC", f"Server berjalan di {SERVER_HOST}:{port}.")
    try:
        _run_kdc_menu(key_store, key_lock)
    finally:
        stop_event.set()
        server_socket.close()
        server_thread.join()


def main() -> None:
    arguments = _parse_arguments()
    key_store = _create_key_store()
    key_lock = threading.Lock()
    _run_server(arguments.port, key_store, key_lock)


if __name__ == "__main__":
    main()
