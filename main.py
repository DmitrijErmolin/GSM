from Cryptodome.Util.number import long_to_bytes
from Cryptodome.Cipher import AES
from math import ceil
from Cryptodome.Random import get_random_bytes
import bitstring


def gf_multiply(x_block, y_block):
    r = "11100001".ljust(128, "0")
    result = 0
    for i in range(0, 128):
        if y_block[i] == "1":
            result = format(int(str(result), 2) ^ int(x_block, 2), "b").rjust(128, "0")
        if x_block[0] == "0":
            x_block = x_block[1:].ljust(128, "0")
        else:
            x_block = format(int(x_block[1:].ljust(128, "0"), 2) ^ int(r, 2), "b").rjust(128, "0")
    return result


def ghash(x_block):
    if len(x_block) % 128 != 0:
        x_block = x_block.rjust(128 - len(x_block) % 128 + len(x_block), "0")
    x_sequence = [x_block[i:i+128] for i in range(0, len(x_block), 128)]
    y_sequence = ["".zfill(128)]
    for item in range(len(x_sequence)):
        y_sequence.append(gf_multiply(format(int(y_sequence[item], 2) ^ int(x_sequence[item], 2), "b").rjust(128, "0"), H_int))
    return bitstring_to_bytes(y_sequence[len(y_sequence) - 1])


def inc(x_s, s):
    x = bitstring.BitArray(x_s).bin
    lsb = (int(x[s:], 2) + 1) % pow(2, s)
    result = x[:len(x)-s] + bin(lsb)[2:]
    return bitstring_to_bytes(result)


def bitstring_to_bytes(s):
    return int(s, 2).to_bytes((len(s) + 7) // 8, byteorder='big')


def gctr(init_cypher_bl, text, key):
    y = list()
    if text == "":
        return ""
    n = ceil(len(text) / 128)
    text_list = [text[i:i+128] for i in range(0, len(text), 128)]
    cipher_block = [init_cypher_bl]
    ciph = AES.new(key, AES.MODE_EAX)
    for i in range(2, n):
        cipher_block.append(inc(cipher_block[i-2], 32))
    for i in range(1, n):
        y.append(format(int(text_list[i-1], 2) ^ int.from_bytes(ciph.encrypt(cipher_block[i-1]), byteorder='big'), "b"))
    y.append(format(int(text_list[n-1], 2) ^ int.from_bytes(ciph.encrypt(cipher_block[len(cipher_block)-1]), byteorder='big'), "b"))
    return ''.join(y)


def make_a_blockJ(vector):
    if len(vector) == 12:
        result_vector = vector.bin + "0" * 31 + "1"
        return bitstring_to_bytes(result_vector)
    else:
        length_vector = len(vector.bin)
        s = 128 * ceil(length_vector / 128) - length_vector
        result_vector = vector.bin + "0" * (s + 64) + bin(length_vector)[2:]
        return ghash(result_vector)




if __name__ == '__main__':
    test_str = input("Введите строку:\n")
    res = ''.join(format(ord(i), 'b') for i in test_str)
    addi_auth_data = bitstring.BitArray(get_random_bytes(8)).bin
    lenght_aad = len(addi_auth_data)
    key = long_to_bytes(pow(2, 128)-1)
    aes = AES.new(key, AES.MODE_EAX)
    H, tag = aes.encrypt_and_digest(bytearray(16))
    H_int = format(int.from_bytes(H, byteorder='big'), "b").rjust(128, "0")
    tag_int = format(int.from_bytes(tag, byteorder='big'), "b").rjust(128, "0")
    init_vector = bitstring.BitArray(bytearray(16))
    j0 = make_a_blockJ(init_vector)
    cipher_text = gctr(inc(j0, 32), res, key)
    if len(cipher_text) % 128 !=0:
        cipher_text = cipher_text.rjust(128 - len(cipher_text) % 128 + len(cipher_text), "0")
    u = 128 * ceil(lenght_aad / 128) - len(cipher_text)
    v = 128 * ceil(lenght_aad / 128) - lenght_aad
    addi_auth_dat = addi_auth_data + ("0"* u) + cipher_text + ("0" * v) + bin(lenght_aad)[2:] + bin(len(cipher_text))[2:]
    tag_cipher = gctr(j0, addi_auth_dat, key)
    print("Cipher text is:", hex(int(cipher_text, 2)))
    print("Tag is : ", hex(int(tag_cipher[:len(tag_int)], 2)))






