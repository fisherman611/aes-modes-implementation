# AES Decryption – CBC and CTR Modes  

## 1. Overview
This project implements **AES decryption** in two modes:  
- **Cipher Block Chaining (CBC)**  
- **Counter Mode (CTR)**  

In both modes, a **16-byte Initialization Vector (IV)** is generated randomly and stored as the **first 16 bytes of the ciphertext**.  
The main goal is to **recover plaintext messages** from the provided ciphertexts.


## 2. How to Build and Run

### 2.1 Environment
- **Language:** Python 3.11+  
- **Required Library:** `cryptography`

### 2.2 Installation
To install the required dependency:
```bash
pip install cryptography
````

### 2.3 Run the Program

Execute the main script:

```bash
python solve.py
```

The program will automatically decrypt all CBC and CTR ciphertexts from the provided dataset and display plaintext outputs for **Questions 1–4**.


## 3. Libraries Used

| Library                                        | Purpose                                                 |
| ---------------------------------------------- | ------------------------------------------------------- |
| `cryptography`       | Provides AES implementation with different cipher modes, and backend for cipher operations |                         
| `binascii`                                     | Converts hexadecimal strings to bytes                   |


## 4. How Decryption Works

### 4.1 CBC Mode

* Extract the first 16 bytes of ciphertext as the **IV**.
* Decrypt each ciphertext block using AES in **CBC mode**.
* Remove **PKCS#5 padding** from the final plaintext block.
* Recovered plaintext is UTF-8 decoded and printed.

**Process Summary:**

1. Split ciphertext → IV + ciphertext blocks
2. Decrypt blocks sequentially with AES-CBC
3. XOR decrypted block with previous ciphertext block (or IV for the first block)
4. Remove padding bytes


### 4.2 CTR Mode

* Extract the first 16 bytes of ciphertext as the **initial counter (IV)**.
* Encrypt the counter value using AES in **ECB mode** to generate a keystream.
* XOR each block of ciphertext with the keystream to obtain plaintext.
* Increment the counter after each block.

**Process Summary:**

1. Split ciphertext → IV + ciphertext blocks
2. Use IV as the counter seed
3. Encrypt counter → produce keystream
4. XOR keystream with ciphertext block
5. Increment counter → repeat


## 5. Recovered Plaintexts

| Question | Mode | Plaintext                                                      |
| -------- | ---- | -------------------------------------------------------------- |
| 1        | CBC  | `Basic CBC mode encryption needs padding.`                     |
| 2        | CBC  | `Our implementation uses rand. IV`                             |
| 3        | CTR  | `CTR mode lets you build a stream cipher from a block cipher.` |
| 4        | CTR  | `Always avoid the two time pad!`                               |



