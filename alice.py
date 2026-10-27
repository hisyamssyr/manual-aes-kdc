import argparse
import json
import secrets
import socket

import common


MAX_NONCE = 2**32


def _step_kdc(
    kdc_addr: tuple[str, int], alice_id: str, peer_id: str, ka: bytes
) -> tuple[bytes, str]:
    n1 = secrets.randbelow(MAX_NONCE) + 1
    common.log("STEP 1", f"Mengirim REQ dari {alice_id} untuk {peer_id}.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect(kdc_addr)
        common.send(sock, {"type": "REQ", "a": alice_id, "b": peer_id, "n1": n1})
        resp = common.recv(sock)

    if resp.get("type") != "RESP":
        raise ValueError("Respons KDC tidak valid")
    for_a, ticket = resp.get("for_a"), resp.get("ticket")
    if not isinstance(for_a, str) or not isinstance(ticket, str):
        raise ValueError("Field respons KDC tidak lengkap")

    common.log("STEP 2", f"for_a={for_a}")
    common.log("STEP 2", f"ticket={ticket}")

    unsealed = common.unseal(ka, for_a).split("|")
    if len(unsealed) != 4 or unsealed[1:] != [alice_id, peer_id, str(n1)]:
        raise ValueError("Data respons KDC tidak cocok dengan permintaan")

    return unsealed[0].encode("ascii"), ticket


def _step_bob(
    bob_addr: tuple[str, int], peer_id: str, ks: bytes, ticket: str
) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(bob_addr)
        common.send(sock, {"type": "TICKET", "ticket": ticket})
        common.log("STEP 3", f"Mengirim tiket ke {peer_id}: {ticket}")

        chal = common.recv(sock)
        if chal.get("type") != "CHALLENGE" or not isinstance(chal.get("data"), str):
            raise ValueError("Respons challenge Bob tidak valid")
        n2 = int(common.unseal(ks, chal["data"]))
        common.log("STEP 4", f"Challenge diterima dari {peer_id}")

        ans = common.seal(ks, str(n2 - 1))
        common.send(sock, {"type": "ANSWER", "data": ans})
        common.log("STEP 5", f"Mengirim jawaban challenge ke {peer_id}")

        auth = common.recv(sock)
        if not auth.get("ok"):
            raise ValueError("Autentikasi ditolak oleh Bob")

        common.log("STEP 5", "Autentikasi berhasil. Memulai chat terenkripsi.")
        common.chat_session(sock, ks)
    except Exception as error:
        sock.close()
        raise error


def _run_protocol(
    kdc_addr: tuple[str, int],
    bob_addr: tuple[str, int],
    alice_id: str,
    peer_id: str,
    ka: bytes,
) -> None:
    try:
        ks, ticket = _step_kdc(kdc_addr, alice_id, peer_id, ka)
        _step_bob(bob_addr, peer_id, ks, ticket)
    except KeyboardInterrupt:
        common.log("ALICE", "Dibatalkan.")
    except Exception as error:
        common.log("ERROR", f"Protokol gagal: {error}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Klien Alice")
    parser.add_argument("--id", default="alice", help="ID Alice")
    parser.add_argument("--peer", default="bob", help="ID Bob")
    args = parser.parse_args()

    with open("config.json", encoding="utf-8") as config_file:
        settings = json.load(config_file)
    kdc_config = settings["kdc"]
    bob_config = settings["bob"]
    kdc_addr = (kdc_config["host"], kdc_config["port"])
    bob_addr = (bob_config["host"], bob_config["port"])
    state = {"ka": common.ask_key("Key Ka: ")}

    def change_key() -> None:
        state["ka"] = common.ask_key("Key Ka: ")
        common.log("KEY", "Key Ka berhasil diubah.")

    def run() -> None:
        _run_protocol(kdc_addr, bob_addr, args.id, args.peer, state["ka"])

    common.run_menu("Alice", {
        "1": ("Ubah key Ka", change_key),
        "2": ("Jalankan Protokol & Chat", run),
    })


if __name__ == "__main__":
    main()
