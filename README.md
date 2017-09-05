# nmapoutputbrowser.py

nmapoutputbrowser.py (NOB) was developed during a red team engagement, where different parts of the network was scanned by different hosts using different scan options and techniques, and we wanted to get a clear overview of discovered ports/services in order to prioritize and choose targets for further exploitation.


NOB parses nmap XML output files and displays a sorted list of open ports. `-v` shows which IPs had ports open and `-vv` shows script scan output.
NOB is usefull when you focus on services and ports, and less on hosts. NOB is great for getting an overview of a network, especially since NOB can parse multiple XML files at once.


Pull requests are welcome.

```
usage: nmapoutputbrowser.py [-h] [-v] [-it] [-sp SILENT_PORT]
                            [-spr SILENT_PORT_RANGE] [-ss SILENT_SERVICE]
                            [-oi]
                            <nmap XML file> [<nmap XML file> ...]

positional arguments:
  <nmap XML file>       nmap XML file renerated with -oX or -oA of nmap

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         Increase verbosity - can be used twice
  -it, --ignore-tcpwrapped
                        hide ports which were found to be tcpwrapped. Default
                        false
  -sp SILENT_PORT, --silent-port SILENT_PORT
                        silence a specific port (protocol agnostic) from
                        output - can be used multiple times
  -spr SILENT_PORT_RANGE, --silent-port-range SILENT_PORT_RANGE
                        silence a specific port range (protocol agnostic) from
                        output e.g. 60000-65535 - can be used multiple times
  -ss SILENT_SERVICE, --silent-service SILENT_SERVICE
                        silence a specific service from output e.g. msrpc -
                        can be used multiple times
  -oi, --only-identified
                        only show ports where version detection could identify
                        the service. Skips 'unknown'. Default false
```
### Example usage

```
$ ./nmapoutputbrowser.py scan1.xml
21/tcp
554/tcp
7070/tcp
$ ./nmapoutputbrowser.py scan1.xml scan2.xml 
21/tcp
80/tcp
554/tcp
7070/tcp
8000/tcp
$ ./nmapoutputbrowser.py scan1.xml scan2.xml -v
21/tcp
|  192.168.87.149 ftp
|  192.168.86.1 tcpwrapped
|  192.168.86.4 ftp
80/tcp
|  192.168.86.4 http
554/tcp
|  192.168.87.149 rtsp
|  192.168.86.1 tcpwrapped
|  192.168.86.4 rtsp
7070/tcp
|  192.168.87.149 tcpwrapped
|  192.168.86.1 tcpwrapped
|  192.168.86.4 realserver
8000/tcp
|  192.168.86.4 http-alt
$ ./nmapoutputbrowser.py scan1.xml scan2.xml -vv
21/tcp
|  192.168.87.149 ftp
|  192.168.86.1 tcpwrapped
|  192.168.86.4 ftp
80/tcp
|  192.168.86.4 http
|    http-favicon: Unknown favicon MD5: 89B932FCC47CF4CA3FAADB0CFDEF89CF
|    http-methods: 
|      Supported Methods: OPTIONS GET HEAD POST PUT DELETE
|      Potentially risky methods: PUT DELETE
|    http-server-header: DNVRS-Webs
|    http-title: index
554/tcp
|  192.168.87.149 rtsp
|  192.168.86.1 tcpwrapped
|  192.168.86.4 rtsp
|    rtsp-methods: ERROR: Script execution failed (use -d to debug)
7070/tcp
|  192.168.87.149 tcpwrapped
|  192.168.86.1 tcpwrapped
|  192.168.86.4 realserver
8000/tcp
|  192.168.86.4 http-alt
$ ./nmapoutputbrowser.py scan1.xml scan2.xml -vv -ss tcpwrapped -ss ftp
80/tcp
|  192.168.86.4 http
|    http-favicon: Unknown favicon MD5: 89B932FCC47CF4CA3FAADB0CFDEF89CF
|    http-methods: 
|      Supported Methods: OPTIONS GET HEAD POST PUT DELETE
|      Potentially risky methods: PUT DELETE
|    http-server-header: DNVRS-Webs
|    http-title: index
554/tcp
|  192.168.87.149 rtsp
|  192.168.86.4 rtsp
|    rtsp-methods: ERROR: Script execution failed (use -d to debug)
7070/tcp
|  192.168.86.4 realserver
8000/tcp
|  192.168.86.4 http-alt
$ ./nmapoutputbrowser.py scan1.xml scan2.xml -vv -it -ss ftp -spr 1000-65535
80/tcp
|  192.168.86.4 http
|    http-favicon: Unknown favicon MD5: 89B932FCC47CF4CA3FAADB0CFDEF89CF
|    http-methods: 
|      Supported Methods: OPTIONS GET HEAD POST PUT DELETE
|      Potentially risky methods: PUT DELETE
|    http-server-header: DNVRS-Webs
|    http-title: index
554/tcp
|  192.168.87.149 rtsp
|  192.168.86.4 rtsp
|    rtsp-methods: ERROR: Script execution failed (use -d to debug)
```

### Dependency installation

```
pip install -r requirements.txt
```
