import secrets


BLOCK_SIZE = 16
KEY_LENGTH = 16
ROUNDS = 10
FIELD_SIZE = 256
AES_REDUCTION = 0x1B
RCON = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36)


def xtime(value: int) -> int:
    shifted = (value << 1) & 0xFF
    if value & 0x80:
        shifted ^= AES_REDUCTION
    return shifted


def gmul(left: int, right: int) -> int:
    result = 0
    for _ in range(8):
        if right & 1:
            result ^= left
        left = xtime(left)
        right >>= 1
    return result


def _multiplicative_inverse(value: int) -> int:
    if value == 0:
        return 0
    for candidate in range(1, FIELD_SIZE):
        if gmul(value, candidate) == 1:
            return candidate
    raise ValueError("Tidak dapat menemukan invers byte")


def _rotate_byte(value: int, amount: int) -> int:
    return ((value << amount) | (value >> (8 - amount))) & 0xFF


def _build_sbox() -> list[int]:
    sbox = []
    for value in range(FIELD_SIZE):
        inverse = _multiplicative_inverse(value)
        substituted = inverse
        for amount in range(1, 5):
            substituted ^= _rotate_byte(inverse, amount)
        sbox.append(substituted ^ 0x63)
    return sbox


SBOX = _build_sbox()
INV_SBOX = [0] * FIELD_SIZE
for _value, _substituted in enumerate(SBOX):
    INV_SBOX[_substituted] = _value


def _validate_key(key: bytes) -> None:
    if len(key) != KEY_LENGTH:
        raise ValueError("Kunci AES harus berukuran 16 byte")


def _validate_state(state: list[int]) -> None:
    if len(state) != BLOCK_SIZE:
        raise ValueError("State AES harus berukuran 16 byte")


def _validate_block(block: bytes) -> None:
    if len(block) != BLOCK_SIZE:
        raise ValueError("Blok AES harus berukuran 16 byte")


def _rot_word(word: list[int]) -> list[int]:
    return word[1:] + word[:1]


def _sub_word(word: list[int]) -> list[int]:
    return [SBOX[value] for value in word]


def expand_key(key: bytes) -> list[bytes]:
    _validate_key(key)
    words = [list(key[index : index + 4]) for index in range(0, KEY_LENGTH, 4)]

    for index in range(4, 4 * (ROUNDS + 1)):
        word = words[index - 1].copy()
        if index % 4 == 0:
            word = _sub_word(_rot_word(word))
            word[0] ^= RCON[index // 4 - 1]
        previous = words[index - 4]
        words.append([previous[position] ^ word[position] for position in range(4)])

    round_keys = []
    for index in range(0, len(words), 4):
        round_key = words[index : index + 4]
        round_keys.append(bytes(value for word in round_key for value in word))
    return round_keys


def sub_bytes(state: list[int]) -> list[int]:
    _validate_state(state)
    return [SBOX[value] for value in state]


def inv_sub_bytes(state: list[int]) -> list[int]:
    _validate_state(state)
    return [INV_SBOX[value] for value in state]


def shift_rows(state: list[int]) -> list[int]:
    _validate_state(state)
    shifted = [0] * BLOCK_SIZE
    for column in range(4):
        for row in range(4):
            source_column = (column + row) % 4
            shifted[column * 4 + row] = state[source_column * 4 + row]
    return shifted


def inv_shift_rows(state: list[int]) -> list[int]:
    _validate_state(state)
    shifted = [0] * BLOCK_SIZE
    for column in range(4):
        for row in range(4):
            source_column = (column - row) % 4
            shifted[column * 4 + row] = state[source_column * 4 + row]
    return shifted


def mix_columns(state: list[int]) -> list[int]:
    _validate_state(state)
    mixed = [0] * BLOCK_SIZE
    for column in range(4):
        offset = column * 4
        a0, a1, a2, a3 = state[offset : offset + 4]
        mixed[offset] = gmul(a0, 2) ^ gmul(a1, 3) ^ a2 ^ a3
        mixed[offset + 1] = a0 ^ gmul(a1, 2) ^ gmul(a2, 3) ^ a3
        mixed[offset + 2] = a0 ^ a1 ^ gmul(a2, 2) ^ gmul(a3, 3)
        mixed[offset + 3] = gmul(a0, 3) ^ a1 ^ a2 ^ gmul(a3, 2)
    return mixed


def inv_mix_columns(state: list[int]) -> list[int]:
    _validate_state(state)
    mixed = [0] * BLOCK_SIZE
    for column in range(4):
        offset = column * 4
        a0, a1, a2, a3 = state[offset : offset + 4]
        mixed[offset] = (
            gmul(a0, 14) ^ gmul(a1, 11) ^ gmul(a2, 13) ^ gmul(a3, 9)
        )
        mixed[offset + 1] = (
            gmul(a0, 9) ^ gmul(a1, 14) ^ gmul(a2, 11) ^ gmul(a3, 13)
        )
        mixed[offset + 2] = (
            gmul(a0, 13) ^ gmul(a1, 9) ^ gmul(a2, 14) ^ gmul(a3, 11)
        )
        mixed[offset + 3] = (
            gmul(a0, 11) ^ gmul(a1, 13) ^ gmul(a2, 9) ^ gmul(a3, 14)
        )
    return mixed


def add_round_key(state: list[int], round_key: bytes) -> list[int]:
    _validate_state(state)
    _validate_key(round_key)
    return [value ^ round_key[index] for index, value in enumerate(state)]


def encrypt_block(key: bytes, block: bytes) -> bytes:
    _validate_key(key)
    _validate_block(block)
    round_keys = expand_key(key)
    state = add_round_key(list(block), round_keys[0])

    for round_number in range(1, ROUNDS):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_number])

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[ROUNDS])
    return bytes(state)


def decrypt_block(key: bytes, block: bytes) -> bytes:
    _validate_key(key)
    _validate_block(block)
    round_keys = expand_key(key)
    state = add_round_key(list(block), round_keys[ROUNDS])

    for round_number in range(ROUNDS - 1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_number])
        state = inv_mix_columns(state)

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    return bytes(state)


def pad(data: bytes) -> bytes:
    padding_length = BLOCK_SIZE - len(data) % BLOCK_SIZE
    return data + bytes([padding_length]) * padding_length


def unpad(data: bytes) -> bytes:
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data padding tidak valid")
    padding_length = data[-1]
    if padding_length < 1 or padding_length > BLOCK_SIZE:
        raise ValueError("Data padding tidak valid")
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        raise ValueError("Data padding tidak valid")
    return data[:-padding_length]


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    return bytes(first ^ second for first, second in zip(left, right))


def encrypt_cbc(key: bytes, plaintext: bytes) -> bytes:
    _validate_key(key)
    initialization_vector = secrets.token_bytes(BLOCK_SIZE)
    padded_plaintext = pad(plaintext)
    previous_block = initialization_vector
    ciphertext = bytearray(initialization_vector)

    for offset in range(0, len(padded_plaintext), BLOCK_SIZE):
        plaintext_block = padded_plaintext[offset : offset + BLOCK_SIZE]
        encrypted_block = encrypt_block(
            key, _xor_bytes(plaintext_block, previous_block)
        )
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block
    return bytes(ciphertext)


def decrypt_cbc(key: bytes, data: bytes) -> bytes:
    _validate_key(key)
    if len(data) < BLOCK_SIZE * 2 or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Data CBC tidak valid")

    initialization_vector = data[:BLOCK_SIZE]
    ciphertext = data[BLOCK_SIZE:]
    previous_block = initialization_vector
    plaintext = bytearray()

    for offset in range(0, len(ciphertext), BLOCK_SIZE):
        ciphertext_block = ciphertext[offset : offset + BLOCK_SIZE]
        decrypted_block = decrypt_block(key, ciphertext_block)
        plaintext.extend(_xor_bytes(decrypted_block, previous_block))
        previous_block = ciphertext_block
    return unpad(bytes(plaintext))
