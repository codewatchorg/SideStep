SideStep
========

SideStep is yet another tool to bypass anti-virus software.  The tool generates Metasploit payloads encrypted using the CryptoPP library (license included), and uses several other techniques to evade AV.

Requirements
============

Software:<BR>
Metasploit Community 4.11.1 - Update 2015031001 (or later)<BR>
Ruby 2.x<BR>
Windows (7 or 8 should work)<BR>
Python 2.7.x<BR>
Visual Studio (free editions should be fine)<BR>
Cygwin with strip utility (if you want to strip debug symbols)<BR>
peCloak (f you want to use it - http://www.securitysift.com/pecloak-py-an-experiment-in-av-evasion/)<BR>

Configuration:
Ruby, Python, strip.exe (if using it), and the cl.exe tool from Visual Studio need to be in your path.  Sorry, I tried to make it compile with ming-gcc with no luck.

Usage
=====

You must configure settings in conf\settings.py, and then you must at a minimum provide the Metasploit listening handler IP and port:
<pre>
  python sidestep.py --ip 192.168.1.1 --port 443
</pre>

If using the defaults, then a source file will be generated in the .\source directory and the executable will be dropped in the .\exe directory.

peCloak Modifications
=====================

If you want to use peCloak in the last step of the executable creation, then you will need to install the pydasm and pefile Python modules.  You will also need to download the SectionDoubleP Python module and save it to the peCloak directory.

Next, you need to make the modifications to pefile that the author of peCloak references on his page.  If pefile was installed as an egg file:
<ol>
<li>Find the egg file, typically in PythonRootDir\Lib\site-packages</li>
<li>Make a copy of the egg file and rename the extension to .zip</li>
<li>Unzip somewhere and rename the folder to the original name, but add .egg.  So if the egg file was named pefile-1.2.10_139-py2.7.egg, then make that the directory name.</li>
<li>Make the necessary changes to pefile.py and remove pefile.pyc</li>
<li>Copy the unzipped folder containing the modified pefile.py back to the PythonRootDir\Lib\site-packages directory and remove the .egg file.</li>
</ol>

If it is installed as an editable Python package, then just find and edit the pefile.py as shown in the peCloak demonstration.

Notes
=====

SideStep generates Meterpreter shellcode, randomly generates an encryption key, and then encrypts the shellcode using AES-128bit with the random key.  All variables and function names are also randomly generated.

In addition, to encrypting the shellcode and assigning random names, it also generates a configurable number of random variables with configurable value lengths.  Surprisingly, this can also help evade AV (read this: https://github.com/nccgroup/metasploitavevasion).

SideStep can also be configured to strip debugging and other symbol information from the final executable and then randomly encode the assembly instructions using peCloak.

Future
======

In the future, I plan on making this more of a framework where additional algorithms can be plugged in and selected more "Metasploit / Veil" style.  I would also like to set it up to randomly organize functions and variables.

At some point, I will better organize and design the system using OOP.

License
=======

I have included the CryptoPP source and a 32bit compiled version of the library, which I believe is ok as I have included the CryptoPP license with this repository.

SideStep is free to modify, use, change, and do whatever else to.