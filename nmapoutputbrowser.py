#!/usr/bin/env python
from __future__ import print_function

import os
import sys
import argparse
from libnmap.parser import NmapParser

theList = []
portIgnoreList = []
serviceIgnoreList = []
verbose = 0

def parseFile(filename):
    def isRange(maybeRange):
        if "-" in maybeRange:
            return True
        else:
            return False

    def portShouldBeIgnored(port):
        for entry in portIgnoreList:
            if isRange(entry):
                entry = entry.split("-")
                if int(entry[0]) <= port[0] and int(entry[1]) >= port[0]:
                    return True
            else:
                if int(entry) == port[0]:
                    return True
        return False

    def hasSeenPort(port):
        for entry in theList:
            if entry[0] == port:
                return True
        return False

    def appendAlreadySeenPort(port, host):
        for entry in theList:
            if entry[0] == port:
                for h in entry[1]:
                    if h.address == host.address:
                        print(str(host.address) + " has already been seen to have port " + str(port) + " open! Skipping...")
                        return
                entry[1].append(host)

    def addNewPort(port, host):
        newEntry = (port, [host])
        theList.append(newEntry)

    nmap_report = NmapParser.parse_fromfile(filename)
    for host in nmap_report.hosts:
        ports = host.get_open_ports()

        if ports:
            for port in ports:
                if not portShouldBeIgnored(port):
                    if hasSeenPort(port):
                        appendAlreadySeenPort(port, host)
                    else:
                        addNewPort(port, host)

def printI(indentation, string):
    prefix = "|" + ("  " * indentation)
    string = string.replace("\n", "\n" + prefix)
    print(prefix + string)

parser = argparse.ArgumentParser()
parser.add_argument("-v", "--verbose", help="Increase verbosity - can be used twice", required=False, default=0, action='count')
parser.add_argument("-it", "--ignore-tcpwrapped", help="hide ports which were found to be tcpwrapped. Default false", required=False, action='store_true', default=False)
parser.add_argument("-sp", "--silent-port", help="silence a specific port (protocol agnostic) from output - can be used multiple times", required=False, action='append')
parser.add_argument("-spr", "--silent-port-range", help="silence a specific port range (protocol agnostic) from output e.g. 60000-65535 - can be used multiple times", required=False, action='append')
parser.add_argument("-ss", "--silent-service", help="silence a specific service from output e.g. msrpc - can be used multiple times", required=False, action='append')
parser.add_argument("-oi", "--only-identified", help="only show ports where version detection could identify the service. Skips 'unknown'. Default false", required=False, action='store_true', default=False)
parser.add_argument("files", metavar='<nmap XML file>', nargs='+', help='nmap XML file renerated with -oX or -oA of nmap')
args = parser.parse_args()

if args.silent_port:
    for entry in args.silent_port:
        portIgnoreList.append(entry)

if args.silent_port_range:
    for entry in args.silent_port_range:
        portIgnoreList.append(entry)

if args.ignore_tcpwrapped:
    serviceIgnoreList.append("tcpwrapped")

if args.silent_service:
    for entry in args.silent_service:
        serviceIgnoreList.append(entry)

if args.only_identified:
    serviceIgnoreList.append('unknown')

# parse
for entry in args.files:
#    try:
        parseFile(entry)
#    except:
#        print(entry + " could not be parsed. Skipping file.", file=sys.stderr)
#        pass

# sort
theList = sorted(theList, key=lambda tup: tup[0])

# print
for entry in theList:
    printPort = True
    if args.verbose > 0:
        printPort = False
        for host in entry[1]:
            service = host.get_service(entry[0][0], entry[0][1])
            if not (not service.service and args.only_identified):
                if not service.service in serviceIgnoreList:
                    printPort = True

    if printPort:
        print(str(entry[0][0]) + "/" + entry[0][1])
    if args.verbose > 0:
        for host in entry[1]:
            service = host.get_service(entry[0][0], entry[0][1])
            if not (not service.service and args.only_identified):
                if not service.service in serviceIgnoreList:
                    if len(service.banner) < 1:
                        printI(1, host.address + " " + service.service)
                    else:
                        printI(1, host.address + " " + service.banner)
                    if args.verbose > 1:
                        scriptRes = service.scripts_results
                        for result in scriptRes:
                            printI(2, result["id"] + ": " + result["output"])
