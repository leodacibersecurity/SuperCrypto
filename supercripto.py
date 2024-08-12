import tkinter as tk
from tkinter import ttk
from tkinter import messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from base64 import b64encode, b64decode

# Funções de criptografia e descriptografia

def generate_key():
    return Fernet.generate_key()

def encrypt_fernet(key, message):
    fernet = Fernet(key)
    encrypted_message = fernet.encrypt(message.encode())
    return encrypted_message.decode()

def decrypt_fernet(key, encrypted_message):
    fernet = Fernet(key)
    decrypted_message = fernet.decrypt(encrypted_message.encode())
    return decrypted_message.decode()

def encrypt_rsa(public_key, message):
    encrypted_message = public_key.encrypt(
        message.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return b64encode(encrypted_message).decode()

def decrypt_rsa(private_key, encrypted_message):
    encrypted_message = b64decode(encrypted_message)
    decrypted_message = private_key.decrypt(
        encrypted_message,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),
                     algorithm=hashes.SHA256(),
                     label=None)
    )
    return decrypted_message.decode()

def encrypt_aes(key, message):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    import os

    key = key.ljust(32)[:32]  # Certifique-se de que a chave tenha 32 bytes
    iv = os.urandom(16)  # Vetor de inicialização aleatório
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    encrypted_message = encryptor.update(padded_message) + encryptor.finalize()
    return b64encode(iv + encrypted_message).decode()

def decrypt_aes(key, encrypted_message):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding
    import os

    key = key.ljust(32)[:32]
    encrypted_message = b64decode(encrypted_message)
    iv = encrypted_message[:16]
    encrypted_message = encrypted_message[16:]
    cipher = Cipher(algorithms.AES(key.encode()), modes.CFB(iv))
    decryptor = cipher.decryptor()
    padded_message = decryptor.update(encrypted_message) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    decrypted_message = unpadder.update(padded_message) + unpadder.finalize()
    return decrypted_message.decode()

def encrypt_caesar(message, shift):
    shift = shift % 26
    encrypted_message = ''.join([chr((ord(char) - 65 + shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 + shift) % 26 + 97) if char.islower() else char for char in message])
    return encrypted_message

def decrypt_caesar(encrypted_message, shift):
    shift = shift % 26
    decrypted_message = ''.join([chr((ord(char) - 65 - shift) % 26 + 65) if char.isupper() else chr((ord(char) - 97 - shift) % 26 + 97) if char.islower() else char for char in encrypted_message])
    return decrypted_message

def encrypt_rail_fence(message, num_rails):
    if num_rails == 1:
        return message

    rails = ['' for _ in range(num_rails)]
    rail = 0
    direction = 1
    for char in message:
        rails[rail] += char
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    return ''.join(rails)

def decrypt_rail_fence(encrypted_message, num_rails):
    if num_rails == 1:
        return encrypted_message

    rails = ['' for _ in range(num_rails)]
    rail = 0
    direction = 1
    for char in encrypted_message:
        rails[rail] += char
        rail += direction
        if rail == 0 or rail == num_rails - 1:
            direction *= -1

    index = 0
    result = []
    for r in range(num_rails):
        for c in range(len(encrypted_message)):
            if r == rail:
                result.append(encrypted_message[index])
                index += 1
            rail = (rail + direction) % num_rails
    return ''.join(result)

def on_encrypt():
    message = entry_message.get()
    choice = encryption_var.get()
    key = entry_key.get()

    if not message:
        result_var.set("Error: Message cannot be empty.")
        return

    if choice in ['Caesar', 'Rail Fence'] and not key:
        result_var.set("Error: Key/Shift cannot be empty.")
        return

    try:
        if choice == 'Fernet':
            key = generate_key()
            encrypted_message = encrypt_fernet(key, message)
            result_var.set(f'Encrypted: {encrypted_message}\nKey: {key.decode()}')

        elif choice == 'RSA':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()
            encrypted_message = encrypt_rsa(public_key, message)
            result_var.set(f'Encrypted: {encrypted_message}')

        elif choice == 'AES':
            if len(key) == 0:
                result_var.set("Error: AES key cannot be empty.")
                return
            encrypted_message = encrypt_aes(key, message)
            result_var.set(f'Encrypted: {encrypted_message}')

        elif choice == 'Caesar':
            try:
                shift = int(key)
                encrypted_message = encrypt_caesar(message, shift)
                result_var.set(f'Encrypted: {encrypted_message}')
            except ValueError:
                result_var.set("Error: Shift must be an integer.")

        elif choice == 'Rail Fence':
            try:
                num_rails = int(key)
                encrypted_message = encrypt_rail_fence(message, num_rails)
                result_var.set(f'Encrypted: {encrypted_message}')
            except ValueError:
                result_var.set("Error: Number of rails must be an integer.")

    except Exception as e:
        result_var.set(f"Error: {str(e)}")

def on_decrypt():
    encrypted_message = entry_message.get()
    choice = encryption_var.get()
    key = entry_key.get()

    if not encrypted_message:
        result_var.set("Error: Encrypted message cannot be empty.")
        return

    if choice in ['Caesar', 'Rail Fence'] and not key:
        result_var.set("Error: Key/Shift cannot be empty.")
        return

    try:
        if choice == 'Fernet':
            key = key.encode()  # Use the provided key
            decrypted_message = decrypt_fernet(key, encrypted_message)
            result_var.set(f'Decrypted: {decrypted_message}')

        elif choice == 'RSA':
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            decrypted_message = decrypt_rsa(private_key, encrypted_message)
            result_var.set(f'Decrypted: {decrypted_message}')

        elif choice == 'AES':
            if len(key) == 0:
                result_var.set("Error: AES key cannot be empty.")
                return
            decrypted_message = decrypt_aes(key, encrypted_message)
            result_var.set(f'Decrypted: {decrypted_message}')

        elif choice == 'Caesar':
            try:
                shift = int(key)
                decrypted_message = decrypt_caesar(encrypted_message, shift)
                result_var.set(f'Decrypted: {decrypted_message}')
            except ValueError:
                result_var.set("Error: Shift must be an integer.")

        elif choice == 'Rail Fence':
            try:
                num_rails = int(key)
                decrypted_message = decrypt_rail_fence(encrypted_message, num_rails)
                result_var.set(f'Decrypted: {decrypted_message}')
            except ValueError:
                result_var.set("Error: Number of rails must be an integer.")

    except Exception as e:
        result_var.set(f"Error: {str(e)}")

def try_caesar_shifts(encrypted_message):
    shifts = range(26)
    decrypted_options = []
    for shift in shifts:
        decrypted_message = decrypt_caesar(encrypted_message, shift)
        decrypted_options.append(f"Shift {shift}: {decrypted_message}")
    return "\n".join(decrypted_options)

def on_try_caesar():
    encrypted_message = entry_message.get()
    if not encrypted_message:
        result_var.set("Error: Encrypted message cannot be empty.")
        return

    decrypted_options = try_caesar_shifts(encrypted_message)
    result_var.set(f"Possible Decryptions:\n{decrypted_options}")

def copy_to_clipboard():
    result_text = result_var.get()
    root.clipboard_clear()
    root.clipboard_append(result_text)
    messagebox.showinfo("Copied", "Text copied to clipboard!")

# Interface gráfica com Tkinter

root = tk.Tk()
root.title("Python Encryption and Decryption Tool")

frame = ttk.Frame(root, padding="10")
frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

# Input de mensagem
ttk.Label(frame, text="Message/Encrypted Message:").grid(row=0, column=0, sticky=tk.W)
entry_message = ttk.Entry(frame, width=50)
entry_message.grid(row=0, column=1, sticky=(tk.W, tk.E))

# Opções de criptografia
ttk.Label(frame, text="Select Encryption Method:").grid(row=1, column=0, sticky=tk.W)
encryption_var = tk.StringVar(value='Fernet')
options = ['Fernet', 'RSA', 'AES', 'Caesar', 'Rail Fence']
for i, option in enumerate(options):
    ttk.Radiobutton(frame, text=option, variable=encryption_var, value=option).grid(row=1, column=i+1, sticky=tk.W)

# Input da chave
ttk.Label(frame, text="Key/Shift/Rails:").grid(row=2, column=0, sticky=tk.W)
entry_key = ttk.Entry(frame, width=20)
entry_key.grid(row=2, column=1, sticky=(tk.W, tk.E))

# Botões de criptografia e descriptografia
btn_encrypt = ttk.Button(frame, text="Encrypt", command=on_encrypt)
btn_encrypt.grid(row=3, column=0, sticky=tk.W, padx=5)

btn_decrypt = ttk.Button(frame, text="Decrypt", command=on_decrypt)
btn_decrypt.grid(row=3, column=1, sticky=tk.W, padx=5)

btn_try_caesar = ttk.Button(frame, text="Try Caesar Shifts", command=on_try_caesar)
btn_try_caesar.grid(row=3, column=2, sticky=tk.W, padx=5)

btn_copy = ttk.Button(frame, text="Copy to Clipboard", command=copy_to_clipboard)
btn_copy.grid(row=3, column=3, sticky=tk.W, padx=5)

# Resultado
result_var = tk.StringVar()
result_label = ttk.Label(frame, textvariable=result_var, wraplength=400)
result_label.grid(row=4, column=0, columnspan=4)

root.mainloop()

