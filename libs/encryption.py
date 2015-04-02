"""
Encrypts the payload from msfvenom
"""

from Crypto.Cipher import AES

# Encrypt with AES-128 in CBC mode
def aesCbc(encKeyLen, encIvLen, encKey, encIv, clearText):
  # Create an AES object
  obj = AES.new(encKey, AES.MODE_CBC, encIv)

  # Add padding if necessary
  padlen = 16 - (len(clearText) % 16)
  clearText += chr(padlen)*padlen

  # Encrypt and then return encrypted value in hex
  ciphertext = obj.encrypt(clearText)
  return ciphertext.encode('hex')