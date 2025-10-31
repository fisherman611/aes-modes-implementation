from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import binascii

def remove_pkcs5_padding(data):
    if len(data) == 0:
        return data

    padding_length = data[-1]

    # Validate padding
    if padding_length > 16 or padding_length == 0:
        return data

    # Verify padding bytes
    if data[-padding_length:] != bytes([padding_length]) * padding_length:
        return data

    return data[:-padding_length]

def decrypt_cbc(key_hex, ciphertext_hex):
    ciphertext_hex = ciphertext_hex.replace(" ", "").replace("\n", "").replace("\r", "")

    # Ensure even-length hex string
    if len(ciphertext_hex) % 2 != 0:
        raise ValueError("Invalid CBC ciphertext: odd-length hex string.")

    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.CBC(iv),
        backend=default_backend()
    )

    decryptor = cipher.decryptor()
    plaintext_padded = decryptor.update(actual_ciphertext) + decryptor.finalize()
    plaintext = remove_pkcs5_padding(plaintext_padded)
    return plaintext.decode('utf-8', errors='ignore')

def decrypt_ctr(key_hex, ciphertext_hex):
    ciphertext_hex = ciphertext_hex.replace(" ", "").replace("\n", "").replace("\r", "")

    # Ensure even-length hex string
    if len(ciphertext_hex) % 2 != 0:
        raise ValueError("Invalid CTR ciphertext: odd-length hex string.")

    key = binascii.unhexlify(key_hex)
    ciphertext = binascii.unhexlify(ciphertext_hex)

    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]

    cipher = Cipher(
        algorithms.AES(key),
        modes.ECB(),
        backend=default_backend()
    )
    encryptor = cipher.encryptor()

    plaintext = bytearray()
    counter = int.from_bytes(iv, byteorder='big')

    for i in range(0, len(actual_ciphertext), 16):
        block = actual_ciphertext[i:i+16]
        counter_bytes = counter.to_bytes(16, byteorder='big')
        encrypted_counter = encryptor.update(counter_bytes)
        for j in range(len(block)):
            plaintext.append(block[j] ^ encrypted_counter[j])
        counter += 1

    return bytes(plaintext).decode('utf-8', errors='ignore')

def main():
    print("=" * 70)
    print("AES CBC and CTR Decryption Program")
    print("=" * 70)

    # CBC parameters (fixed full ciphertexts)
    cbc_key = "140b41b22a29beb4061bda66b6747e14"
    cbc_ciphertext1 = "4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81"
    cbc_ciphertext2 = "5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253"

    # CTR parameters
    ctr_key = "36f18357be4dbd77f050515c73fcf9f2"
    ctr_ciphertext1 = "69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329"
    ctr_ciphertext2 = "770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451"

    print("\n--- CBC Mode Decryption ---\n")
    print("Question 1 - CBC Ciphertext 1:")
    plaintext1 = decrypt_cbc(cbc_key, cbc_ciphertext1)
    print(f"Plaintext: {plaintext1}\n")

    print("Question 2 - CBC Ciphertext 2:")
    plaintext2 = decrypt_cbc(cbc_key, cbc_ciphertext2)
    print(f"Plaintext: {plaintext2}\n")

    print("\n--- CTR Mode Decryption ---\n")
    print("Question 3 - CTR Ciphertext 1:")
    plaintext3 = decrypt_ctr(ctr_key, ctr_ciphertext1)
    print(f"Plaintext: {plaintext3}\n")

    print("Question 4 - CTR Ciphertext 2:")
    plaintext4 = decrypt_ctr(ctr_key, ctr_ciphertext2)
    print(f"Plaintext: {plaintext4}\n")

    print("=" * 70)

if __name__ == "__main__":
    main()
