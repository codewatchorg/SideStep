"""
Encrypts the payload from msfvenom
"""

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

# Encrypt with AES-128 in CBC mode
def aesCbc(encKeyLen, encIvLen, encKey, encIv, clearText):
  # Create an AES object
  obj = AES.new(encKey.encode("utf8"), AES.MODE_CBC, encIv.encode("utf8"))

  # Add padding if necessary
  #padlen = 16 - (len(clearText) % 16)
  #clearText += chr(padlen)*padlen

  # Encrypt and then return encrypted value in hex
  ciphertext = obj.encrypt(pad(clearText, AES.block_size))
  return ciphertext.hex()