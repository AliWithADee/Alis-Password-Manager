from hashlib import sha512


def password_hashed_once(plain_pass: str):
    return sha512(plain_pass.encode()).hexdigest()


def password_hashed_twice(plain_pass: str):
    return sha512(password_hashed_once(plain_pass).encode()).hexdigest()


def binary_to_decimal(binary):
    decimal = 0
    for b in range(len(binary) - 1, -1, -1):
        bit = int(binary[b])
        power = len(binary) - (b + 1)
        decimal += bit * (2 ** power)
    return decimal


def binary_to_text(text_bin):
    binaries = text_bin.split(" ")
    text = ""
    for binary in binaries:
        decimal = binary_to_decimal(binary)
        text += chr(decimal)
    return text


def text_to_binary(text):
    text_bin = ""
    for c in range(len(text)):
        char = text[c]
        decimal = ord(char)

        char_bin = bin(decimal).replace('0b', '')
        x = char_bin[::-1]
        while len(x) < 7:
            x += '0'
        char_bin = x[::-1]

        text_bin += char_bin
        if c < len(text) - 1: text_bin += " "
    return text_bin


def xor(text_bin, key_bin):
    if len(text_bin) > len(key_bin): return

    result_bin = ""
    for b in range(len(text_bin)):
        if key_bin[b] == " ":
            result_bin += " "
        elif key_bin[b] == text_bin[b]:
            result_bin += "0"
        else:
            result_bin += "1"

    return result_bin


def encrypt(plain_text, key):
    key_bin = text_to_binary(key)
    plain_bin = text_to_binary(plain_text)

    cipher_bin = xor(plain_bin, key_bin)

    return binary_to_text(cipher_bin)


def decrypt(cipher_text, key):
    key_bin = text_to_binary(key)
    cipher_bin = text_to_binary(cipher_text)

    plain_bin = xor(cipher_bin, key_bin)

    return binary_to_text(plain_bin)
