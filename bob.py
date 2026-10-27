import argparse
import json
import secrets
import socket

import common


MAX_NONCE = 2**32


def _handle_connection(
    conn: socket.socket, addr: tuple[str, int], kb: bytes, peer_id: str
) -> None:
    with conn:
        try:
            msg = common.recv(conn)
            if msg.get("type") != "TICKET" or not isinstance(msg.get("ticket"), str):
                raise ValueError("Pesan tiket tidak valid")
            ticket_hex = msg["ticket"]
            common.log("STEP 3", f"Tiket diterima dari {addr[0]}:{addr[1]}: {ticket_hex}")

            plaintext = common.unseal(kb, ticket_hex)
            parts = plaintext.split("|")
            if len(parts) != 2:
                raise ValueError("Isi tiket tidak sesuai format")
            ks_str, sender_id = parts
            if sender_id != peer_id:
                raise ValueError(f"Identitas {sender_id} tidak sesuai dengan {peer_id}")
            ks = ks_str.encode("ascii")

            n2 = secrets.randbelow(MAX_NONCE) + 1
            chal_hex = common.seal(ks, str(n2))
            common.send(conn, {"type": "CHALLENGE", "data": chal_hex})
            common.log("STEP 4", f"Challenge dikirim ke {peer_id}: {chal_hex}")

            ans = common.recv(conn)
            if ans.get("type") != "ANSWER" or not isinstance(ans.get("data"), str):
                raise ValueError("Pesan jawaban challenge tidak valid")
            ans_val = common.unseal(ks, ans["data"])
            if ans_val != str(n2 - 1):
                common.send(conn, {"type": "AUTH", "ok": False})
                common.log("ERROR", "Verifikasi challenge gagal.")
                return

            common.send(conn, {"type": "AUTH", "ok": True})
            common.log("STEP 5", "Autentikasi berhasil. Memulai chat terenkripsi.")
            common.chat_session(conn, ks)
        except Exception as error:
            common.log("ERROR", f"Handshake gagal: {error}")


def _wait_for_alice(
    bind_host: str, port: int, kb: bytes, peer_id: str
) -> None:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    conn = None
    try:
        server.bind((bind_host, port))
        server.listen(1)
        common.log("BOB", f"Menunggu koneksi dari {peer_id} di port {port} (Ctrl+C untuk batal)...")
        conn, addr = server.accept()
    except KeyboardInterrupt:
        common.log("BOB", "Dibatalkan.")
        return
    except OSError as error:
        common.log("ERROR", f"Gagal membuka port: {error}")
        return
    finally:
        server.close()

    if conn:
        _handle_connection(conn, addr, kb, peer_id)


def main() -> None:
    parser = argparse.ArgumentParser(description="Node Bob")
    parser.add_argument("--id", default="bob", help="ID Bob")
    parser.add_argument("--peer", default="alice", help="ID lawan bicara (Alice)")
    args = parser.parse_args()
    with open("config.json", encoding="utf-8") as config_file:
        settings = json.load(config_file)
    bob_config = settings["bob"]
    bind_host = bob_config.get("bind_host", "0.0.0.0")
    port = bob_config["port"]

    state = {"kb": common.ask_key("Key Bob: ")}

    def change_key() -> None:
        state["kb"] = common.ask_key("Key Bob: ")
        common.log("KEY", "Key Bob berhasil diubah.")

    def run_session() -> None:
        _wait_for_alice(bind_host, port, state["kb"], args.peer)

    common.run_menu("Bob", {
        "1": ("Ubah key Bob", change_key),
        "2": ("Tunggu Alice & Chat", run_session),
    })


if __name__ == "__main__":
    main()
