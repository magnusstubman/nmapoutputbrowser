# Nmapoutputbrowser - nob.py
This tool aims to help pentesters find and identify low-hanging fruits faster.

nob.py was developed during a red team engagement, where different parts of the network was scanned by different hosts using different scan options and techniques, and we wanted to get a clear overview of discovered ports/services in order to prioritize and choose targets for further exploitation.


nob.py parses nmap XML output files and displays a sorted list of open ports. `-v` shows which IPs had ports open and `-vv` shows version scan output. `-vvv` shows script scan results.
nob.py is useful when you focus on services and ports, and less on hosts. nob.py is great for getting an overview of a network, especially since nob.py can parse multiple XML files at once.

Pull requests are welcome.

### Example usage

```
$ ./nmapoutputbrowser.py scan1.xml
21/tcp
554/tcp
7070/tcp
```

```
$ ./nmapoutputbrowser.py scan1.xml scan2.xml 
21/tcp
80/tcp
554/tcp
7070/tcp
8000/tcp
```

```
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
```

```
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
```

```
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
```

```
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
