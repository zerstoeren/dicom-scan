#!/usr/bin/env python

import sys
import os
import argparse
import io
import json
import time
import netaddr
import threading
from socket import *
from pydicom import *
from pynetdicom3 import AE

def dicomscan(server, port, results_file):
    print "Attempting DICOM scan on " + '%s' % server + '\n'
    ts = time.strftime("%Y-%m-%d %H:%M")
    try:
        ae = AE(scu_sop_class=['1.2.840.10008.1.1'])
        peerassoc = ae.associate(server, port)
        dicom_entry = peerassoc.send_c_echo()
        peerassoc.release()
        if '%s' % dicom_entry is not None:
            if results_file is not None:
                with print_lock:
                    with open(results_file, 'a+') as outfile:
                        dicom_data = 'host: ' + '%s' % server + '\n' + 'is_dicom: true\ndicom_info:' + '%s' % dicom_entry + '\ndicom_port: ' + '%s' % port + '\ntimestamp: ' + '%s' % ts + '\n\n'
                        outfile.write(dicom_data)
            else:
                with print_lock:
                    print ("[+] " + '%s' % server + ": " + '%s' % dicom_entry + '\n')
        else:
            pass
    except:
        try:
            connector = socket(AF_INET, SOCK_STREAM)
            connector.settimeout(1)
            connector.connect(('%s' % server, port))
            connector.send('Friendly Portscanner\r\n')
            dicom_entry = connector.recv(2048)
            connector.close()
            if results_file is not None:
                with print_lock:
                    with open(results_file, 'a+') as outfile:
                       dicom_data = 'host: ' + '%s' % server + '\n' + 'is_dicom: false\ndicom_info:' + '%s' % dicom_entry + '\ndicom_port: ' + '%s' % port + '\ntimestamp: ' + '%s' % ts + '\n\n'
                       outfile.write(dicom_data)
            else:
                with print_lock:
                    print ("[-] " + '%s' % server + ": " + '%s' % dicom_entry + '\n')
                    pass
        except Exception, errorcode:
            if errorcode[0] == "timed out":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            elif errorcode[0] == "connection refused":
                print server + ": connection " + errorcode[0] + "\n"
                pass
            else:
                pass

def thread_check(server, results_file):
    global semaphore

    try:
        dicomscan(server, port, results_file)
    except Exception as e:
        with print_lock:
           print "[ERROR] [%s] - %s" % (server, e)
           pass
    finally:
        semaphore.release()

if __name__ == "__main__":
    dicomparser = argparse.ArgumentParser(description="DICOM Scanner")
    dicomparser.add_argument("-netrange", type=str, required=False, help="CIDR Block")
    dicomparser.add_argument("-ip", type=str, required=False, help="IP address to scan")
    dicomparser.add_argument("-port", type=int, required=True, help="Ports to scan for DICOM")
    dicomparser.add_argument("-results_file", type=str, required=False, help="Results File")
    dicomparser.add_argument("-packet_rate", default=1, type=int, required=False, help="Packet rate")
    dicomargs = dicomparser.parse_args()

    semaphore = threading.BoundedSemaphore(value=dicomargs.packet_rate)
    print_lock = threading.Lock()

    if dicomargs.ip is not None:
        dicomscan(dicomargs.ip, dicomargs.port, dicomargs.results_file)

    elif dicomargs.netrange is not None:
       for ip in netaddr.IPNetwork(dicomargs.netrange).iter_hosts():
           dicomscan(str(ip), dicomargs.port, dicomargs.results_file)

    elif not dicomargs.packet_rate and dicomargs.netrange:
       for ip in netaddr.IPNetwork(dicomargs.netrange).iter_hosts():
           semaphore.acquire()
           dicomthread = threading.Thread(target=thread_check, args=(str(ip), dicomargs.results_file))
           dicomthread.start()
           dicomthread.join()
    else:
        print "Please provide with either -ip or -netrange.  Or ./dicomscanner.py -h for help.."
        exit
