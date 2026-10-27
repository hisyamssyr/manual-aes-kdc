import ast
import secrets
import unittest
from pathlib import Path

import aes


class AesTest(unittest.TestCase):
    def test_encrypt_fips197_vector_b(self) -> None:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        plaintext = bytes.fromhex("3243f6a8885a308d313198a2e0370734")
        expected = bytes.fromhex("3925841d02dc09fbdc118597196a0b32")

        ciphertext = aes.encrypt_block(key, plaintext)

        self.assertEqual(ciphertext, expected)
        self.assertEqual(aes.decrypt_block(key, ciphertext), plaintext)

    def test_encrypt_fips197_vector_c1(self) -> None:
        key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        plaintext = bytes.fromhex("00112233445566778899aabbccddeeff")
        expected = bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a")

        ciphertext = aes.encrypt_block(key, plaintext)

        self.assertEqual(ciphertext, expected)
        self.assertEqual(aes.decrypt_block(key, ciphertext), plaintext)

    def test_key_expansion_fips197_vector_b(self) -> None:
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        expected = bytes.fromhex("d014f9a8c9ee2589e13f0cc8b6630ca6")

        self.assertEqual(aes.expand_key(key)[-1], expected)

    def test_sbox_and_inverse_sbox(self) -> None:
        self.assertEqual(aes.SBOX[0x00], 0x63)
        self.assertEqual(aes.SBOX[0x53], 0xED)
        for value in range(256):
            self.assertEqual(aes.INV_SBOX[aes.SBOX[value]], value)

    def test_inverse_transformations(self) -> None:
        state = list(range(16))

        self.assertEqual(aes.inv_shift_rows(aes.shift_rows(state)), state)
        self.assertEqual(aes.inv_mix_columns(aes.mix_columns(state)), state)
        self.assertEqual(aes.inv_sub_bytes(aes.sub_bytes(state)), state)

    def test_cbc_round_trip_for_lengths_zero_to_forty(self) -> None:
        key = secrets.token_bytes(aes.KEY_LENGTH)
        for length in range(41):
            plaintext = bytes((index * 13) % 256 for index in range(length))
            encrypted = aes.encrypt_cbc(key, plaintext)
            self.assertEqual(aes.decrypt_cbc(key, encrypted), plaintext)

    def test_cbc_uses_a_new_iv(self) -> None:
        key = secrets.token_bytes(aes.KEY_LENGTH)
        plaintext = b"plaintext yang sama"

        first = aes.encrypt_cbc(key, plaintext)
        second = aes.encrypt_cbc(key, plaintext)

        self.assertNotEqual(first, second)
        self.assertEqual(aes.decrypt_cbc(key, first), plaintext)
        self.assertEqual(aes.decrypt_cbc(key, second), plaintext)

    def test_padding_adds_a_full_block_for_aligned_data(self) -> None:
        plaintext = b"A" * aes.BLOCK_SIZE
        padded = aes.pad(plaintext)

        self.assertEqual(len(padded), aes.BLOCK_SIZE * 2)
        self.assertEqual(aes.unpad(padded), plaintext)

    def test_unpad_rejects_invalid_padding(self) -> None:
        with self.assertRaises(ValueError):
            aes.unpad(b"A" * aes.BLOCK_SIZE)
        with self.assertRaises(ValueError):
            aes.unpad(b"A" * 15 + b"\x02")

    def test_cbc_rejects_invalid_lengths(self) -> None:
        key = bytes(range(aes.KEY_LENGTH))

        with self.assertRaises(ValueError):
            aes.decrypt_cbc(key, b"\x00" * aes.BLOCK_SIZE)
        with self.assertRaises(ValueError):
            aes.decrypt_cbc(key, b"\x00" * 17)

    def test_python_files_do_not_import_crypto_libraries(self) -> None:
        forbidden_modules = {
            "".join(("cryp", "to")),
            "".join(("crypto", "graphy")),
            "".join(("pyae", "s")),
            "".join(("Cryp", "to")),
            "".join(("hash", "lib")),
        }
        project_root = Path(__file__).resolve().parent

        for path in project_root.glob("*.py"):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported = [alias.name.split(".")[0] for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported = [node.module.split(".")[0]]
                else:
                    continue
                self.assertTrue(
                    forbidden_modules.isdisjoint(imported),
                    f"Import terlarang di {path.name}",
                )


if __name__ == "__main__":
    unittest.main()
