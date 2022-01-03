"""
Contains the random generation code for functions, variables, and data
"""

import random

randomFirstChar = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_'
randomVarChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_'
randomChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-'
encChars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-!@#$%^&*()+=[]{}|:;\'/?<>.,'

# Generate a random function
def genFunc(randomFuncSize):
  firstFuncChar = ''.join(random.SystemRandom().choice(randomFirstChar) for _ in range(1))
  remFuncChar = ''.join(random.SystemRandom().choice(randomVarChars) for _ in range(randomFuncSize-1))
  return firstFuncChar + remFuncChar

# Generate a random variable
def genVar(randomVarSize):
  firstVarChar = ''.join(random.SystemRandom().choice(randomFirstChar) for _ in range(1))
  remVarChar = ''.join(random.SystemRandom().choice(randomVarChars) for _ in range(randomVarSize-1))
  return firstVarChar + remVarChar

# Generate random data
def genData(dataLen):
  paddingChars = ''.join(random.SystemRandom().choice(randomChars) for _ in range(dataLen))
  return paddingChars

# Generate an encryption key
def genKey(encKeyLen):
  encKey = ''.join(random.SystemRandom().choice(encChars) for _ in range(encKeyLen))
  return encKey

# Generate an IV for encryption
def genIv(encIvLen):
  encIv = ''.join(random.SystemRandom().choice(encChars) for _ in range(encIvLen))
  return encIv