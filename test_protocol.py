import socket
import threading
import unittest

import alice
import common
import kdc


class ProtocolIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.kdc_port = 0
        self.ka = b"1111222233334444"
        self.kb = b"5555666677778888"
        self.keys = {"alice": self.ka, "bob": self.kb}
        self.lock = threading.Lock()
        self.stop_kdc = threading.Event()

        self.kdc_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.kdc_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.kdc_sock.bind(("127.0.0.1", self.kdc_port))
        self.kdc_sock.listen()
        self.kdc_port = self.kdc_sock.getsockname()[1]

        self.kdc_thread = threading.Thread(
            target=kdc._serve,
            args=(self.kdc_sock, self.stop_kdc, self.keys, self.lock),
            daemon=True,
        )
        self.kdc_thread.start()

    def tearDown(self) -> None:
        self.stop_kdc.set()
        try:
            self.kdc_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            self.kdc_sock.close()
        else:
            self.kdc_sock.close()
        self.kdc_thread.join(timeout=1)

    def test_kdc_step_1_and_2_success(self) -> None:
        ks, ticket = alice._step_kdc(
            ("127.0.0.1", self.kdc_port), "alice", "bob", self.ka
        )
        self.assertEqual(len(ks), 16)
        self.assertTrue(bool(ticket))

        ticket_plain = common.unseal(self.kb, ticket)
        parts = ticket_plain.split("|")
        self.assertEqual(len(parts), 2)
        self.assertEqual(parts[0], ks.decode("ascii"))
        self.assertEqual(parts[1], "alice")

    def test_kdc_wrong_alice_key_fails(self) -> None:
        wrong_ka = b"9999999999999999"
        with self.assertRaises(ValueError):
            alice._step_kdc(
                ("127.0.0.1", self.kdc_port), "alice", "bob", wrong_ka
            )

    def test_kdc_unknown_participant_fails(self) -> None:
        with self.assertRaises(Exception):
            alice._step_kdc(
                ("127.0.0.1", self.kdc_port), "charlie", "bob", self.ka
            )

    def test_bob_handshake_steps_3_to_5_success(self) -> None:
        ks, ticket = alice._step_kdc(
            ("127.0.0.1", self.kdc_port), "alice", "bob", self.ka
        )

        bob_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bob_server.bind(("127.0.0.1", 0))
        bob_server.listen(1)
        bob_port = bob_server.getsockname()[1]

        def bob_worker() -> None:
            conn, _ = bob_server.accept()
            msg = common.recv(conn)
            plain = common.unseal(self.kb, msg["ticket"]).split("|")
            bob_ks = plain[0].encode("ascii")
            common.send(
                conn,
                {"type": "CHALLENGE", "data": common.seal(bob_ks, "12345")},
            )
            ans = common.recv(conn)
            val = common.unseal(bob_ks, ans["data"])
            self.assertEqual(val, "12344")
            common.send(conn, {"type": "AUTH", "ok": True})
            msg_in = common.recv(conn)
            self.assertEqual(
                common.unseal(bob_ks, msg_in["data"]), "Halo Bob!"
            )
            common.send(
                conn,
                {"type": "MSG", "data": common.seal(bob_ks, "Halo Alice!")},
            )
            conn.close()

        t_bob = threading.Thread(target=bob_worker, daemon=True)
        t_bob.start()

        alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alice_sock.connect(("127.0.0.1", bob_port))
        common.send(alice_sock, {"type": "TICKET", "ticket": ticket})

        chal = common.recv(alice_sock)
        n2 = int(common.unseal(ks, chal["data"]))

        common.send(
            alice_sock,
            {"type": "ANSWER", "data": common.seal(ks, str(n2 - 1))},
        )
        auth = common.recv(alice_sock)
        self.assertTrue(auth.get("ok"))

        common.send(
            alice_sock,
            {"type": "MSG", "data": common.seal(ks, "Halo Bob!")},
        )
        reply = common.recv(alice_sock)
        self.assertEqual(common.unseal(ks, reply["data"]), "Halo Alice!")

        alice_sock.close()
        t_bob.join(timeout=1)
        bob_server.close()

    def test_bob_rejects_wrong_challenge_answer(self) -> None:
        ks, ticket = alice._step_kdc(
            ("127.0.0.1", self.kdc_port), "alice", "bob", self.ka
        )

        bob_server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        bob_server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        bob_server.bind(("127.0.0.1", 0))
        bob_server.listen(1)
        bob_port = bob_server.getsockname()[1]

        def bob_worker() -> None:
            conn, _ = bob_server.accept()
            msg = common.recv(conn)
            bob_ks = common.unseal(self.kb, msg["ticket"]).split("|")[0].encode(
                "ascii"
            )
            common.send(
                conn,
                {"type": "CHALLENGE", "data": common.seal(bob_ks, "5000")},
            )
            ans = common.recv(conn)
            ans_val = common.unseal(bob_ks, ans["data"])
            if ans_val != "4999":
                common.send(conn, {"type": "AUTH", "ok": False})
            conn.close()

        t = threading.Thread(target=bob_worker, daemon=True)
        t.start()

        alice_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        alice_sock.connect(("127.0.0.1", bob_port))
        common.send(alice_sock, {"type": "TICKET", "ticket": ticket})
        common.recv(alice_sock)
        common.send(
            alice_sock, {"type": "ANSWER", "data": common.seal(ks, "9999")}
        )
        auth = common.recv(alice_sock)
        self.assertFalse(auth.get("ok"))

        alice_sock.close()
        t.join(timeout=1)
        bob_server.close()

    def test_dynamic_key_rotation(self) -> None:
        new_ka = b"abcdefabcdefabcd"
        with self.lock:
            self.keys["alice"] = new_ka

        with self.assertRaises(ValueError):
            alice._step_kdc(
                ("127.0.0.1", self.kdc_port), "alice", "bob", self.ka
            )

        ks, ticket = alice._step_kdc(
            ("127.0.0.1", self.kdc_port), "alice", "bob", new_ka
        )
        self.assertEqual(len(ks), 16)


if __name__ == "__main__":
    unittest.main()
