# Use strip.exe to remove debugging symbols
useStrip = 1

# Use peCloak to perform additional encoding on the binary
usePeCloak = 1
peCloakPath = 'C:\\Tools\\peCloak\\'

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

# Path to Metasploit Meterpreter payload generator
msfpath = 'c:/metasploit/apps/pro/msf3/'

# Metasploit Meterpreter payload generator command
msfvenom = 'msfvenom'

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
vsPath = 'C:\\Program Files (x86)\\Microsoft Visual Studio 14.0\\VC'

# Windows SDK path
sdkPath = 'C:\\Program Files (x86)\\Microsoft SDKs\\Windows\\v7.1A'

# Windows Kit Include path
kitPathIncl = 'C:\\Program Files (x86)\\Windows Kits\\10\\Include\\10.0.10240.0\\ucrt'

# Windows Kit Lib path
kitPathLib = 'C:\\Program Files (x86)\\Windows Kits\\10\\Lib\\10.0.10240.0\\ucrt\\x86'