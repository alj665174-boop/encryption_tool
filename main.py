from aes_tool import aes_encrypt, aes_decrypt
from rsa_tool import generate_rsa_keys, rsa_encrypt, rsa_decrypt

password = "strongpassword123"

encrypted = aes_encrypt(password, "Hello -team 👩‍🏫")
print("Encrypted -AES:", encrypted)

decrypted = aes_decrypt(password, encrypted)
print("Decrypted -AES:", decrypted)

private_key, public_key = generate_rsa_keys()
cipher = rsa_encrypt(public_key, "RSA -Secret")
print("RSA -Decrypted:", rsa_decrypt(private_key, cipher))
