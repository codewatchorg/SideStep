"""
Compiles the CryptoPP lib file
"""
import subprocess
import sys
import os
import time

def compileCryptoPP(path_delim, sourceDir, vsPath, sdkPath, kitPathIncl):
# Create lists to store CryptoPP file names
  cryptoppSource = ['3way', 'adler32', 'algebra', 'algparam', 'arc4', 'asn', 'authenc', 'base32', 'base64', 'basecode', 'bfinit', 'blowfish', 'blumshub', 'camellia', 'cast', 'casts', 'cbcmac', 'ccm', 'channels', 'cmac', 'cpu', 'crc', 'cryptlib', 'default', 'des', 'dessp', 'dh', 'dh2', 'dsa', 'eax', 'ec2n', 'ecp', 'elgamal', 'emsa2', 'esign', 'files', 'filters', 'fips140', 'fipstest', 'gcm', 'gf256', 'gf2_32', 'gf2n', 'gfpcrypt', 'gost', 'gzip', 'hex', 'hmac', 'hrtimer', 'ida', 'idea', 'integer', 'luc', 'mars', 'marss', 'md2', 'md4', 'md5', 'misc', 'modes', 'mqueue', 'mqv', 'nbtheory', 'network', 'oaep', 'osrng', 'panama', 'pkcspad', 'polynomi', 'pssr', 'pubkey', 'queue', 'rabin', 'randpool', 'rc2', 'rc5', 'rc6', 'rdtables', 'rijndael', 'ripemd', 'rng', 'rsa', 'rw', 'safer', 'salsa', 'seal', 'seed', 'serpent', 'sha', 'sha3', 'shacal2', 'shark', 'sharkbox', 'simple', 'skipjack', 'socketft', 'sosemanuk', 'square', 'squaretb', 'strciphr', 'tea', 'tftables', 'tiger', 'tigertab', 'trdlocal', 'ttmac', 'twofish', 'vmac', 'wait', 'wake', 'whrlpool', 'winpipes', 'xtr', 'xtrcrypt', 'zdeflate', 'zinflate', 'zlib']

  # Create variables to store strings of .cpp and .obj files for compilation
  cryptoCpp = []
  cryptoObj = ''

  # Create variable to store cl.exe options
  cryptoPPOptions = '/c /Zi /nologo /W3 /WX- /O2 /Ob2 /Oi /Oy /GL /D NDEBUG /D _WINDOWS /D USE_PRECOMPILED_HEADERS /D WIN32 /D _VC80_UPGRADE=0x0710 /GF /Gm- /EHsc /MT /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /Yu"pch.h" /Fp"' + sourceDir + path_delim + 'cryptlib.pch" /Gd /TP /analyze- /errorReport:prompt /Fo"' + sourceDir + path_delim + path_delim + '" /I"' + sourceDir + '" /I"' + vsPath + path_delim + 'include" /I"' + vsPath + path_delim + 'atlmfc' + path_delim + 'include" /I"' + sdkPath + path_delim + 'Include" /I"' + kitPathIncl + '" '

  # Loop through CryptoPP .cpp file lists and create strings for compilation
  multiple = 10
  cppFileNum = len(cryptoppSource)
  totalLists = cppFileNum/multiple
  remainderLists = cppFileNum-(totalLists*multiple)

  for x in xrange(0, totalLists+1):
    tmpStr = ''

    if x == totalLists:
      for y in range(0, remainderLists):
        tmpStr += sourceDir + path_delim + cryptoppSource[x*multiple+y] + '.cpp' + ' '
    else:
      for y in range(0, multiple):
        tmpStr += sourceDir + path_delim + cryptoppSource[x*multiple+y] + '.cpp' + ' '

    cryptoCpp.append(cryptoPPOptions + tmpStr)

  # Create a string of all .obj files
  for item in cryptoppSource:
    cryptoObj += sourceDir + path_delim + item + '.obj' + ' '

  # Finish the string for .obj files
  cryptoObj += sourceDir + path_delim + 'pch.obj ' + sourceDir + path_delim + 'dll.obj ' + sourceDir + path_delim + 'iterhash.obj'

  pchOptions = '/c /Zi /nologo /W3 /WX- /O2 /Ob2 /Oi /Oy /GL /D NDEBUG /D _WINDOWS /D USE_PRECOMPILED_HEADERS /D WIN32 /D _VC80_UPGRADE=0x0710 /GF /Gm- /EHsc /MT /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /Yc"pch.h" /Fo"' + sourceDir + path_delim + path_delim + '" /Fp"' + sourceDir + path_delim + 'cryptlib.pch" /Gd /TP /analyze- /errorReport:prompt /I"' + vsPath + path_delim + 'include" /I"' + vsPath + path_delim + 'atlmfc' + path_delim + 'include" /I"' + sdkPath + path_delim + 'Include" /I"' + kitPathIncl + '" /I"' + sourceDir + '" ' + sourceDir + path_delim + 'pch.cpp'

  dll_and_iterhash_Options = '/c /Zi /nologo /W3 /WX- /O2 /Ob2 /Oi /Oy /GL /D NDEBUG /D _WINDOWS /D USE_PRECOMPILED_HEADERS /D WIN32 /D _VC80_UPGRADE=0x0710 /GF /Gm- /EHsc /MT /GS /Gy /fp:precise /Zc:wchar_t /Zc:forScope /Zc:inline /Gd /TP /analyze- /errorReport:prompt /Fo"' + sourceDir + path_delim + path_delim + '" /I"' + sourceDir + '" /I"' + vsPath + path_delim + 'include" /I"' + vsPath + path_delim + 'atlmfc' + path_delim + 'include" /I"' + sdkPath + path_delim + 'Include" /I"' + kitPathIncl + '" ' + sourceDir + path_delim + 'dll.cpp ' + sourceDir + path_delim + 'iterhash.cpp'

  libOptions = '/OUT:"' + sourceDir + path_delim + 'cryptlib.lib" /NOLOGO /LTCG ' + cryptoObj

  subprocess.Popen('cl ' + pchOptions, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  time.sleep(5)

  subprocess.Popen('cl ' + dll_and_iterhash_Options, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  time.sleep(5)

  for item in cryptoCpp:
    subprocess.Popen('cl ' + item, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    time.sleep(7)

  subprocess.Popen('lib ' + libOptions, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  time.sleep(5)