from cryptography.fernet import Fernet
#from getpass import getpass
import stdiomask
import csv
import os

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def generate_key_from_password(password, salt=b'salt_1234', iterations=100):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key

# Save the key to a file for later use
def save_key(key, filename):
    with open(filename, 'wb') as key_file:
        key_file.write(key)

# Load the key from a file
def load_key(filename):
    with open(filename, 'rb') as key_file:
        return key_file.read()
    
def encrypt_password(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

def decrypt_password(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

def check_master_key():
    key_filename = 'key.key'
    if not os.path.exists(key_filename):
        master_key = stdiomask.getpass('Ingrese una nueva clave maestra\n')
        # If key file doesn't exist, generate a new key and save it
        key = generate_key_from_password(master_key)
        save_key(key, key_filename)
    else:
        # Load the key from the existing file
        master_key = stdiomask.getpass('Ingrese la clave maestra\n')
        key = load_key(key_filename)
        if key == generate_key_from_password(master_key):
            print('Clave maestra correcta')
            return key
        else:
            print('Clave maestra incorrecta')
            return None
        
def check_passwords_file():
    password_filename = 'passwords.csv'
    if not os.path.exists(password_filename):
        with open('passwords.csv', 'a', newline='') as file:
            writer_object = csv.writer(file)
            writer_object.writerow(['Service', 'Username', 'Password'])

def main():
    check_passwords_file()
    key = check_master_key()
    while not key:
       key = check_master_key() 
    
    running = True
    while running:
        opcion = int(input('1) Agregar cuenta\n2) Obtener cuenta\n3) Salir\n'))
        match opcion:
            case 1:
            # Encrypt the password
                service = input('Ingrese el servicio: ')
                username = input('Ingrese el nombre de usuario: ')
                password_to_encrypt = stdiomask.getpass('Ingrese la contraseña: ')
                encrypted_password = encrypt_password(password_to_encrypt, key)

                with open('passwords.csv', 'a', newline='') as file:
                    writer_object = csv.writer(file)
                    writer_object.writerow([service, username, encrypted_password.decode()])
            # Decrypt the password        
            case 2:
                with open('passwords.csv', 'r') as file: 
                    reader = csv.DictReader(file)
                    for row in reader:
                        decrypted_password = decrypt_password(row['Password'].encode(), key)
                        print(f"Service: {row['Service']}, Username: {row['Username']}, Password: {decrypted_password}")
            case 3:
                running = False
                
if __name__ == "__main__":
    main()
