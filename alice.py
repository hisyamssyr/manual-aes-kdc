import argparse
import secrets
import socket

import common


DEFAULT_ALICE_ID = "alice"
DEFAULT_PEER_ID = "bob"
MAX_NONCE = 2**32
KEY_LENGTH = 16


def _is_valid_identity(identity: str) -> bool:
    return bool(identity) and identity.isascii() and identity.isalnum()


def _parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Klien Alice")
    parser.add_argument("--kdc", required=True, help="Alamat KDC dalam format ip:port")
    parser.add_argument("--bob", required=True, help="Alamat Bob dalam format ip:port")
    parser.add_argument("--id", default=DEFAULT_ALICE_ID, help="ID Alice")
    parser.add_argument("--peer", default=DEFAULT_PEER_ID, help="ID Bob")
    arguments = parser.parse_args()

    try:
        arguments.kdc_address = common.parse_hostport(arguments.kdc)
        arguments.bob_address = common.parse_hostport(arguments.bob)
    except ValueError as error:
        parser.error(str(error))
    if not _is_valid_identity(arguments.id):
        parser.error("ID Alice harus berupa huruf atau angka.")
    if not _is_valid_identity(arguments.peer):
        parser.error("ID Bob harus berupa huruf atau angka.")
    return arguments


def _decode_response(
    response: dict[str, object],
    alice_key: bytes,
    request: dict[str, object],
) -> tuple[bytes, str]:
    if response.get("type") != "RESP":
        raise ValueError("Respons KDC tidak valid")
    for_alice = response.get("for_a")
    ticket = response.get("ticket")
    if not isinstance(for_alice, str) or not isinstance(ticket, str):
        raise ValueError("Field respons KDC tidak valid")

    plaintext = common.unseal(alice_key, for_alice)
    fields = plaintext.split("|")
    expected = [
        str(request["a"]),
        str(request["b"]),
        str(request["n1"]),
    ]
    if len(fields) != 4 or fields[1:] != expected:
        raise ValueError("Respons KDC tidak sesuai dengan permintaan")
    if len(fields[0]) != KEY_LENGTH or not fields[0].isalnum():
        raise ValueError("Session key dari KDC tidak valid")
    return fields[0].encode("ascii"), ticket


def _request_session(
    kdc_address: tuple[str, int],
    alice_id: str,
    peer_id: str,
    alice_key: bytes,
) -> tuple[bytes, str]:
    nonce = secrets.randbelow(MAX_NONCE) + 1
    request = {"type": "REQ", "a": alice_id, "b": peer_id, "n1": nonce}
    common.log("STEP 1", f"Mengirim REQ dari {alice_id} untuk {peer_id}.")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(kdc_address)
        common.send(sock, request)
        response = common.recv(sock)

    session_key, ticket = _decode_response(response, alice_key, request)
    for_alice = response["for_a"]
    common.log("STEP 2", f"for_a={for_alice}")
    common.log("STEP 2", f"ticket={ticket}")
    return session_key, ticket


def _clear_session(state: dict[str, object]) -> None:
    state.pop("session_key", None)
    state.pop("ticket", None)


def _change_key(state: dict[str, object]) -> None:
    state["key"] = common.ask_key("Key Ka: ")
    _clear_session(state)
    common.log("KEY", "Key Ka berhasil diubah.")


def _run_protocol(
    state: dict[str, object],
    kdc_address: tuple[str, int],
    alice_id: str,
    peer_id: str,
) -> None:
    alice_key = state.get("key")
    if not isinstance(alice_key, bytes):
        common.log("ERROR", "Key Ka belum tersedia.")
        return
    try:
        session_key, ticket = _request_session(
            kdc_address, alice_id, peer_id, alice_key
        )
    except (ConnectionError, OSError, TypeError, ValueError) as error:
        _clear_session(state)
        common.log("ERROR", f"Protokol gagal: {error}")
        return
    state["session_key"] = session_key
    state["ticket"] = ticket
    common.log("AUTH", "Langkah 1-2 berhasil; tiket Bob tersimpan.")


def main() -> None:
    arguments = _parse_arguments()
    state = {"key": common.ask_key("Key Ka: ")}

    def change_key() -> None:
        _change_key(state)

    def run_protocol() -> None:
        _run_protocol(state, arguments.kdc_address, arguments.id, arguments.peer)

    menu_options = {
        "1": ("Ubah key Ka", change_key),
        "2": ("Jalankan protokol langkah 1-2", run_protocol),
    }
    common.run_menu("Alice", menu_options)


if __name__ == "__main__":
    main()
