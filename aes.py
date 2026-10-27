import secrets


BLOCK_SIZE = 16
KEY_LENGTH = 16
ROUNDS = 10
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def xtime(value: int) -> int:
    return ((value << 1) ^ (0x1B if value & 0x80 else 0)) & 0xFF


def gmul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = xtime(left)
        right >>= 1
    return result


def _build_sbox() -> tuple[list[int], list[int]]:
    sbox = [0] * 256
    inv_sbox = [0] * 256
    for val in range(256):
        inv = 0
        if val != 0:
            for cand in range(1, 256):
                if gmul(val, cand) == 1:
                    inv = cand
                    break
        sub = inv
        for shift in range(1, 5):
            sub ^= ((inv << shift) | (inv >> (8 - shift))) & 0xFF
        sub ^= 0x63
        sbox[val] = sub
        inv_sbox[sub] = val
    return sbox, inv_sbox


SBOX, INV_SBOX = _build_sbox()


def expand_key(key: bytes) -> list[bytes]:
    if len(key) != KEY_LENGTH:
        raise ValueError("Key AES harus 16 byte")
    words = [list(key[i : i + 4]) for i in range(0, KEY_LENGTH, 4)]
    for i in range(4, 4 * (ROUNDS + 1)):
        temp = words[i - 1].copy()
        if i % 4 == 0:
            temp = [SBOX[b] for b in temp[1:] + temp[:1]]
            temp[0] ^= RCON[i // 4 - 1]
        words.append([p ^ q for p, q in zip(words[i - 4], temp)])
    return [
        bytes(b for word in words[i : i + 4] for b in word)
        for i in range(0, len(words), 4)
    ]


def sub_bytes(state: list[int]) -> list[int]:
    return [SBOX[b] for b in state]


def inv_sub_bytes(state: list[int]) -> list[int]:
    return [INV_SBOX[b] for b in state]


def shift_rows(state: list[int]) -> list[int]:
    return [state[((c + r) % 4) * 4 + r] for c in range(4) for r in range(4)]


def inv_shift_rows(state: list[int]) -> list[int]:
    return [state[((c - r) % 4) * 4 + r] for c in range(4) for r in range(4)]


def mix_columns(state: list[int]) -> list[int]:
    mixed = [0] * BLOCK_SIZE
    for c in range(4):
        o = c * 4
        a0, a1, a2, a3 = state[o : o + 4]
        mixed[o] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        mixed[o + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        mixed[o + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        mixed[o + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return mixed


def inv_mix_columns(state: list[int]) -> list[int]:
    mixed = [0] * BLOCK_SIZE
    for c in range(4):
        o = c * 4
        a0, a1, a2, a3 = state[o : o + 4]
        mixed[o] = gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        mixed[o + 1] = gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        mixed[o + 2] = gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        mixed[o + 3] = gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
    return mixed


def add_round_key(state: list[int], round_key: bytes) -> list[int]:
    return [b ^ k for b, k in zip(state, round_key)]


def encrypt_block(key: bytes, block: bytes) -> bytes:
    if len(key) != KEY_LENGTH or len(block) != BLOCK_SIZE:
        raise ValueError("Key dan block harus 16 byte")
    round_keys = expand_key(key)
    state = add_round_key(list(block), round_keys[0])
    for r in range(1, ROUNDS):
        state = add_round_key(
            mix_columns(shift_rows(sub_bytes(state))), round_keys[r]
        )
    state = add_round_key(shift_rows(sub_bytes(state)), round_keys[ROUNDS])
    return bytes(state)


def decrypt_block(key: bytes, block: bytes) -> bytes:
    if len(key) != KEY_LENGTH or len(block) != BLOCK_SIZE:
        raise ValueError("Key dan block harus 16 byte")
    round_keys = expand_key(key)
    state = add_round_key(list(block), round_keys[ROUNDS])
    for r in range(ROUNDS - 1, 0, -1):
        state = inv_mix_columns(
            add_round_key(inv_sub_bytes(inv_shift_rows(state)), round_keys[r])
        )
    state = add_round_key(inv_sub_bytes(inv_shift_rows(state)), round_keys[0])
    return bytes(state)


def pad(data: bytes) -> bytes:
    pad_len = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([pad_len]) * pad_len


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Padding tidak valid")
    pad_len = data[-1]
    if (
        pad_len < 1
        or pad_len > BLOCK_SIZE
        or data[-pad_len:] != bytes([pad_len]) * pad_len
    ):
        raise ValueError("Padding tidak valid")
    return data[:-pad_len]


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    if len(key) != KEY_LENGTH:
        raise ValueError("Key harus 16 byte")
    iv = secrets.token_bytes(BLOCK_SIZE)
    padded = pad(plaintext)
    out = bytearray(iv)
    prev = iv
    for i in range(0, len(padded), BLOCK_SIZE):
        chunk = bytes(p ^ c for p, c in zip(padded[i : i + BLOCK_SIZE], prev))
        enc = encrypt_block(key, chunk)
        out.extend(enc)
        prev = enc
    return bytes(out)


def decrypt_cbc(key: bytes, data: bytes) -> bytes:
    if (
        len(key) != KEY_LENGTH
        or len(data) < BLOCK_SIZE * 2
        or len(data) % BLOCK_SIZE != 0
    ):
        raise ValueError("Data CBC tidak valid")
    iv, ct = data[:BLOCK_SIZE], data[BLOCK_SIZE:]
    pt = bytearray()
    prev = iv
    for i in range(0, len(ct), BLOCK_SIZE):
        block = ct[i : i + BLOCK_SIZE]
        dec = decrypt_block(key, block)
        pt.extend(bytes(d ^ p for d, p in zip(dec, prev)))
        prev = block
    return unpad(bytes(pt))
