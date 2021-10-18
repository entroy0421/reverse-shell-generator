# reverse-shell-generator

## Usage
```
██████╗ ███████╗██╗   ██╗███████╗██████╗ ███████╗███████╗    ███████╗██╗  ██╗███████╗██╗     ██╗     
██╔══██╗██╔════╝██║   ██║██╔════╝██╔══██╗██╔════╝██╔════╝    ██╔════╝██║  ██║██╔════╝██║     ██║     
██████╔╝█████╗  ██║   ██║█████╗  ██████╔╝███████╗█████╗      ███████╗███████║█████╗  ██║     ██║     
██╔══██╗██╔══╝  ╚██╗ ██╔╝██╔══╝  ██╔══██╗╚════██║██╔══╝      ╚════██║██╔══██║██╔══╝  ██║     ██║     
██║  ██║███████╗ ╚████╔╝ ███████╗██║  ██║███████║███████╗    ███████║██║  ██║███████╗███████╗███████╗
╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝    ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚══════╝
                                                                                                     
 ██████╗ ███████╗███╗   ██╗███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗                         
██╔════╝ ██╔════╝████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗                        
██║  ███╗█████╗  ██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝                        
██║   ██║██╔══╝  ██║╚██╗██║██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗                        
╚██████╔╝███████╗██║ ╚████║███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║                        
 ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝    by entroy
usage: reverse_shell_generator.py [-h] [-ip IP] [-p PORT] [-t TYPE]

optional arguments:
  -h, --help            show this help message and exit
  -ip IP                External ip address.
  -p PORT, --port PORT  Port you want to reverse.
  -t TYPE, --type TYPE  Type: awk, bash_tcp, bash_udp, c, dart, golang, groovy, java, lua_linux, lua_windows, ncat, nc, nc_openbsd,
                        nc_busybox, nodejs, openssl, perl, perl_windows, php, powershell, python, python_no_space, python_ipv6,
                        python_ipv6_no_space, python_code, ruby, ruby_windows, socat, telnet. Default: bash_tcp
  -b [BYPASS], --bypass [BYPASS]
                        For bypassing waf.
  -c1 CHARACTER1, --character1 CHARACTER1
                        Character to replace.
  -c2 CHARACTER2, --character2 CHARACTER2
                        Replace to new character.
```
### Example
```
python3 reverse_shell_generator.py -ip 127.0.0.1 -p 4000 -t bash_tcp
```
![](https://i.imgur.com/jg5LBLE.png)
```
python3 reverse_shell_generator.py -b
```
![](https://i.imgur.com/DpoYbeE.png)

```
python3 reverse_shell_generator.py -b -c1 bash -c2 BASH 
```
![](https://i.imgur.com/qeWnn02.png)


## Reference
> https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md