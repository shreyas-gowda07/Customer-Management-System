from pwdlib import PasswordHash
password_hash=PasswordHash.recommended()
password="9353161904"
hashed=password_hash.hash(password)
print(hashed)