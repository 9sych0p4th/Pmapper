#!/usr/bin/python3

import argparse
import socket
import re 

from scapy.all import *




# Class Utils
class Utils:
    def checkIp(domain):
        if (re.match(r"^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$", domain)):
            return True

        elif(re.match(r"[a-zA-Z0-9]+\.[a-z]{3}\.*[a-z]{0,2}", domain)):
            return False

        else:
            return None



    def checkPort(p):
        if (p == 20 or p == 21):
            return f"{p} Open FTP"

        elif(p == 22):
            return f"{p} Open SSH"
        
        elif(p == 23):
            return f"{p} Open TELNET"

        elif(p == 25 or p == 587):
            return f"{p} Open SMTP"

        elif(p == 53):
            return f"{p} Open DNS"

        elif(p == 67):
            return f"{p} Open DHCP"

        elif(p == 69):
            return f"{p} Open TFTP"

        elif(p == 79):
            return f"{p} Open FINGER"

        elif(p == 80):
            return f"{p} Open HTTP"

        elif(p == 110):
            return f"{p} Open POP"

        elif(p == 123):
            return f"{p} Open NTP"

        elif(p == 143):
            return f"{p} Open IMAP"

        elif(p == 161 or p == 162):
            return f"{p} Open SNMP"

        elif(p == 443):
            return f"{p} Open HTTPS"

        else:
            return f"{p} Open"
        


# Class with scanners
class Scan:
    def ping(ip):
        pIP = IP(dst=ip)
        pICMP = ICMP()

        answ = sr1(pIP/pICMP, verbose=0, timeout=0.2)

        if(answ):
            if(answ[ICMP].type == 0):
                print("[+] the host is UP")
                return True

        else:
            print("[-] The host is not up")
            return False

    

    def synScan(ip, portini, portfin=None):
        count = 0
        open = []

        if(portfin != None):
            for p in range(portini, portfin):
                pIP = IP(dst=ip) 
                pTCP = TCP(flags="S", dport=p)

                answ = sr1(pIP/pTCP, verbose=0, timeout=0.2)

                if(answ[TCP].flags == "SA"):
                    open.append(f"{Utils.checkPort(answ[TCP].sport)}")

                else:
                    count += 1

            return count, open

        else:
            pIP = IP(dst=ip) 
            pTCP = TCP(flags="S", dport=portini)

            answ = sr1(pIP/pTCP, verbose=0, timeout=0.2)

            if(answ[TCP].flags == "SA"):
                open.append(f"{Utils.checkPort(portini)}")

            else:
                count += 1

            return count, open



    def tcpScan(ip, portini, portfin=None):
        count = 0 
        open = []

        if(portfin != None):
            for p in range(portini, portfin):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)
                
                con = s.connect_ex((ip, p))

                if(con == 0):
                    open.append(f"{Utils.checkPort(p)}")
                
                else:
                    count += 1

            return count, open


        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)
                
            con = s.connect_ex((ip, portini))

            if(con == 0):
                open.append(f"{Utils.checkPort(portini)}")
                
            else:
                count += 1

            return count, open
            

    def tcpScanBanner(ip, portini, portfin=None):
        count = 0 
        open = []

        if(portfin != None):
            for p in range(portini, portfin):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.2)

                con = s.connect_ex((ip, p))

                if(con == 0):
                    if(p == 21):
                        banner = s.recv(200)
                        open.append(f"{Utils.checkPort(p)} {str(banner)}")

                    elif(p == 22):
                        banner = s.recv(200)
                        open.append(f"{Utils.checkPort(p)} {str(banner)}")

                    elif(p == 25):
                        banner = s.recv(200)
                        open.append(f"{Utils.checkPort(p)} {str(banner)}")

                    elif(p == 80):
                        s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                        banner = s.recv(1000)

                        try:
                            server = re.search(r"Server: [a-zA-Z0-9]+ ?[a-zA-Z0-9]+", str(banner)).group(0)
                        except AttributeError:
                            server = "could not capture server"

                        open.append(f"{Utils.checkPort(p)} {server}")
                        
                else:
                    count += 1
            
            return count, open

        else:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.2)

            con = s.connect_ex((ip, portini))

            if(con == 0):
                if(portini == 21):
                    banner = s.recv(200)
                    open.append(f"{Utils.checkPort(portini)} {str(banner)}")

                elif(portini == 22):
                    banner = s.recv(200)
                    open.append(f"{Utils.checkPort(portini)} {str(banner)}")

                elif(portini == 25):
                    banner = s.recv(200)
                    open.append(f"{Utils.checkPort(portini)} {str(banner)}")

                elif(portini == 80):
                    s.send(b"HEAD / HTTP/1.1\r\n\r\n")
                    banner = s.recv(1000) 
                    
                    try:
                        server = re.search(r"Server: [a-zA-Z0-9]+ ?[a-zA-Z0-9]+", str(banner)).group(0)
                    except AttributeError:
                        server = "could not capture server"

                    open.append(f"{Utils.checkPort(portini)} {server}")
                        
            else:
                count += 1
            
            return count, open

    def udpScan(ip, portini, portfin=None):
        count = 0 
        open = []

        if(portfin != None):
            for p in range(portini, portfin):
                pIP = IP(dst=ip)
                pUDP = UDP(dport=p)

                
                resp = sr1(pIP/pUDP, verbose=0, timeout=0.2)

                try:
                    if resp[ICMP]:
                        count += 1
                    
                    else:
                        open.append(f"{pUDP.dport} Open|Filtred")

                except TypeError:
                    count += 1
                    continue

            return count, open

        else:
            pIP = IP(dst=ip)
            pUDP = UDP(dport=portini)

            try:
                resp = sr1(pIP/pUDP, verbose=0, timeout=0.2)

            except TypeError:
                print(portini)

            try:
                if resp[ICMP]:
                    count += 1
                    
                else:
                    open.append(f"{pUDP.dport} Open|Filtred")

            except TypeError:
                count += 1
                pass

            return count, open
                


# Arguments
# ===========================================================

parser = argparse.ArgumentParser(description="Pmapper is just a simple open source portscanner that is available on github =D")

parser.add_argument("-sP", "--pingscan", help="performs a pingscan: -sP 192.168.0.1")
parser.add_argument("-sT", "--tcpscan", help="does a tcpscan: -sT 192.168.0.1 ")
parser.add_argument("-sV", "--bannerscan", help="does a tcpScan with banner grabbing: -sV 192.168.0.1")
parser.add_argument("-sS", "--synscan", help="performs a synscan: -sS 192.168.0.1 ")
parser.add_argument("-sU", "--udpscan", help="perform a udpscan: -sU 192.168.0.1 ")

parser.add_argument("-sTn", "--tcpscannoping", help="does a tcpscan without the initial ping: -sTn 192.168.0.1")
parser.add_argument("-sVn", "--bannerscannoping", help="does a tcpScan with banner grabbing without the initial ping: -sV 192.168.0.1")
parser.add_argument("-sSn", "--synscannoping", help="performs a synscan without the initial ping: -sS 192.168.0.1 ")
parser.add_argument("-sUn", "--udpscannoping", help="perform a udpscan without the initial ping: -sU 192.168.0.1 ")

parser.add_argument("-p", "--ports", help="sets the ports for the scan: -p All, -p Low, -p High, -p 10, -p 40-60")
parser.add_argument("-O", "--output", help="creates an output file with the scan information: -O filename.txt ")

args = parser.parse_args()




# The main Prog
def main(args):
    try: 
        if(not args.ports):
            # Com output 
            if(args.output):
                # TCP scan com ping e output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                                
                    else:
                        exit()
                        
                # Banner scan com ping e output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                                
                    else:
                        exit()

                # syn scan com ping e output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                        check = Scan.ping(ip)
                        file = open(args.output, "a")

                        if(check == True):
                            count, ports = Scan.synScan(ip, 0, 1023)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")
                                
                        else:
                            exit()

                    # Udp scan com ping e output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                            
                    else:
                        exit()


                    # TCP scan sem ping com output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")


                    # Banner scan sem ping com output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                    # syn scan sem ping e output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.synScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                    # udp scan sem ping e output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.udpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

            else:
                if(args.pingscan):
                    check = Utils.checkIp(args.pingscan)

                    if(check == True):
                        ip = args.pingscan
                    elif(check == False):
                        ip = socket.gethostbyname(args.pingscan)

                    Scan.ping(ip)

                    

                # TCP scan com ping sem output 
                elif(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                                
                    else:
                        exit()
                        
                # Banner scan com ping sem output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                            
                    else:
                        exit()

                    # syn scan com ping sem output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.synScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                            
                    else:
                        exit()

                # Udp scan com ping sem output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                                
                    else:
                        exit()



                # TCP scan sem ping sem output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    count, ports = Scan.tcpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")


                    # Banner scan sem ping sem output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # syn scan sem ping sem output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    count, ports = Scan.synScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # udp scan sem ping sem output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    count, ports = Scan.udpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")


        # Todas as portas 
        elif(args.ports.lower() == "all"):
            # Com output 
            if(args.output):
                # TCP scan com ping e output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Banner scan com ping e output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # syn scan com ping e output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.synScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping e output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping com output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScan(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")
                                    


                # Banner scan sem ping com output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScanBanner(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                # syn scan sem ping e output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.synScan(ip, 0, 65535)

                    for p in ports:
                        print(p)

                    file.close()
                    print(f"[+] {count} ports close !")

                # udp scan sem ping e output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.udpScan(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

            else:
                # TCP scan com ping sem output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()
                
                # Banner scan com ping sem output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")


                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # syn scan com ping sem output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.synScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")


                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping sem output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")


                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping sem output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    count, ports = Scan.tcpScan(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")


                    print(f"[+] {count} ports close !")
                        


                # Banner scan sem ping sem output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    count, ports = Scan.tcpScanBanner(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # syn scan sem ping sem output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    count, ports = Scan.synScan(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # udp scan sem ping sem output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    count, ports = Scan.udpScan(ip, 0, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")
        
        # Apenas nas portas altas
        elif(args.ports.lower() == "high"):
            # Com output 
            if(args.output):
                # TCP scan com ping e output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()
                
                # Banner scan com ping e output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # syn scan com ping e output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.synScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping e output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping com output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")


                # Banner scan sem ping com output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScanBanner(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                # syn scan sem ping com output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.synScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")


                # udp scan sem ping com output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.udpScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")
                    
                    file.close()
                    print(f"[+] {count} ports close !")

            else:
                # TCP scan com ping sem output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()
                
                # Banner scan com ping sem output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # syn scan com ping sem output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.synScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping sem output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 1024, 65535)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping sem output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    count, ports = Scan.tcpScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")


                # Banner scan sem ping sem output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    count, ports = Scan.tcpScanBanner(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # syn scan sem ping sem output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    count, ports = Scan.synScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # udp scan sem ping sem output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    count, ports = Scan.udpScan(ip, 1024, 65535)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")
            

        elif(args.ports.lower() == "low"):
            # Com output 
            if(args.output):
                # TCP scan com ping e output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()
                
                # Banner scan com ping e output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                # syn scan com ping e output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.synScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping e output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)
                    file = open(args.output, "a")

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping com output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")


                # Banner scan sem ping com output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                # syn scan sem ping e output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.synScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

                # udp scan sem ping e output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    file = open(args.output, "a")

                    count, ports = Scan.udpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                        file.write(p)
                    print("")

                    file.close()
                    print(f"[+] {count} ports close !")

            else:
                # TCP scan com ping sem output 
                if(args.tcpscan):
                    check = Utils.checkIp(args.tcpscan)

                    if(check == True):
                        ip = args.tcpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()
                
                # Banner scan com ping sem output
                elif(args.bannerscan):
                    check = Utils.checkIp(args.bannerscan)

                    if(check == True):
                        ip = args.bannerscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # syn scan com ping sem output 
                elif(args.synscan):
                    check = Utils.checkIp(args.synscan)

                    if(check == True):
                        ip = args.synscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.synScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()

                # Udp scan com ping sem output
                elif(args.udpscan):
                    check = Utils.checkIp(args.udpscan)

                    if(check == True):
                        ip = args.udpscan

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscan)

                    check = Scan.ping(ip)

                    if(check == True):
                        count, ports = Scan.udpScan(ip, 0, 1023)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")
                        
                    else:
                        exit()



                # TCP scan sem ping sem output 
                elif(args.tcpscannoping):
                    check = Utils.checkIp(args.tcpscannoping)

                    if(check == True):
                        ip = args.tcpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.tcpscannoping)

                    count, ports = Scan.tcpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")


                # Banner scan sem ping sem output 
                elif(args.bannerscannoping):
                    check = Utils.checkIp(args.bannerscannoping)

                    if(check == True):
                        ip = args.bannerscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.bannerscannoping)

                    count, ports = Scan.tcpScanBanner(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # syn scan sem ping sem output 
                elif(args.synscannoping):
                    check = Utils.checkIp(args.synscannoping)

                    if(check == True):
                        ip = args.synscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.synscannoping)

                    count, ports = Scan.synScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")

                # udp scan sem ping sem output
                elif(args.udpscannoping):
                    check = Utils.checkIp(args.udpscannoping)

                    if(check == True):
                        ip = args.udpscannoping

                    elif(check == False):
                        ip = socket.gethostbyname(args.udpscannoping)

                    count, ports = Scan.udpScan(ip, 0, 1023)

                    print("")
                    for p in ports:
                        print(p)
                    print("")

                    print(f"[+] {count} ports close !")
        
        elif("-" in args.ports or args.ports.isdigit()):
            ports = args.ports.split("-")
            cont = 0

            for p in ports:
                cont += 1

            if(cont == 1):
                p1 = int(ports[0])

                # Com output 
                if(args.output):
                    # TCP scan com ping e output 
                    if(args.tcpscan):
                        check = Utils.checkIp(args.tcpscan)

                        if(check == True):
                            ip = args.tcpscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.tcpscan)

                        check = Scan.ping(ip)
                        file = open(args.output, "a")

                        if(check == True):
                            count, ports = Scan.tcpScan(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()
                        
                    # Banner scan com ping e output
                    elif(args.bannerscan):
                        check = Utils.checkIp(args.bannerscan)

                        if(check == True):
                            ip = args.bannerscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.bannerscan)

                        check = Scan.ping(ip)
                        file = open(args.output, "a")

                        if(check == True):
                            count, ports = Scan.tcpScanBanner(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()

                    # syn scan com ping e output 
                    elif(args.synscan):
                        check = Utils.checkIp(args.synscan)

                        if(check == True):
                            ip = args.synscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.synscan)

                        check = Scan.ping(ip)
                        file = open(args.output, "a")

                        if(check == True):
                            count, ports = Scan.synScan(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()

                    # Udp scan com ping e output
                    elif(args.udpscan):
                        check = Utils.checkIp(args.udpscan)

                        if(check == True):
                            ip = args.udpscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.udpscan)

                        check = Scan.ping(ip)
                        file = open(args.output, "a")

                        if(check == True):
                            count, ports = Scan.udpScan(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()



                    # TCP scan sem ping com output 
                    elif(args.tcpscannoping):
                        check = Utils.checkIp(args.tcpscannoping)

                        if(check == True):
                            ip = args.tcpscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.tcpscannoping)

                        file = open(args.output, "a")

                        count, ports = Scan.tcpScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")


                    # Banner scan sem ping com output 
                    elif(args.bannerscannoping):
                        check = Utils.checkIp(args.bannerscannoping)

                        if(check == True):
                            ip = args.bannerscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.bannerscannoping)

                        file = open(args.output, "a")

                        count, ports = Scan.tcpScanBanner(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")

                    # syn scan sem ping e output 
                    elif(args.synscannoping):
                        check = Utils.checkIp(args.synscannoping)

                        if(check == True):
                            ip = args.synscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.synscannoping)

                        file = open(args.output, "a")

                        count, ports = Scan.synScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")

                    # udp scan sem ping e output
                    elif(args.udpscannoping):
                        check = Utils.checkIp(args.udpscannoping)

                        if(check == True):
                            ip = args.udpscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.udpscannoping)

                        file = open(args.output, "a")

                        count, ports = Scan.udpScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                            file.write(p)
                        print("")

                        file.close()
                        print(f"[+] {count} ports close !")

                else:
                    # TCP scan com ping sem output 
                    if(args.tcpscan):
                        check = Utils.checkIp(args.tcpscan)

                        if(check == True):
                            ip = args.tcpscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.tcpscan)

                        check = Scan.ping(ip)

                        if(check == True):
                            count, ports = Scan.tcpScan(ip, int(p1))
                            
                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()
                        
                    # Banner scan com ping sem output
                    elif(args.bannerscan):
                        check = Utils.checkIp(args.bannerscan)

                        if(check == True):
                            ip = args.bannerscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.bannerscan)

                        check = Scan.ping(ip)

                        if(check == True):
                            count, ports = Scan.tcpScanBanner(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()

                    # syn scan com ping sem output 
                    elif(args.synscan):
                        check = Utils.checkIp(args.synscan)

                        if(check == True):
                            ip = args.synscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.synscan)

                        check = Scan.ping(ip)

                        if(check == True):
                            count, ports = Scan.synScan(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()

                    # Udp scan com ping sem output
                    elif(args.udpscan):
                        check = Utils.checkIp(args.udpscan)

                        if(check == True):
                            ip = args.udpscan

                        elif(check == False):
                            ip = socket.gethostbyname(args.udpscan)

                        check = Scan.ping(ip)

                        if(check == True):
                            count, ports = Scan.udpScan(ip, p1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")
                            
                        else:
                            exit()



                    # TCP scan sem ping sem output 
                    elif(args.tcpscannoping):
                        check = Utils.checkIp(args.tcpscannoping)

                        if(check == True):
                            ip = args.tcpscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.tcpscannoping)

                        count, ports = Scan.tcpScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")


                    # Banner scan sem ping sem output 
                    elif(args.bannerscannoping):
                        check = Utils.checkIp(args.bannerscannoping)

                        if(check == True):
                            ip = args.bannerscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.bannerscannoping)

                        count, ports = Scan.tcpScanBanner(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")

                    # syn scan sem ping sem output 
                    elif(args.synscannoping):
                        check = Utils.checkIp(args.synscannoping)

                        if(check == True):
                            ip = args.synscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.synscannoping)

                        count, ports = Scan.synScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")

                    # udp scan sem ping sem output
                    elif(args.udpscannoping):
                        check = Utils.checkIp(args.udpscannoping)

                        if(check == True):
                            ip = args.udpscannoping

                        elif(check == False):
                            ip = socket.gethostbyname(args.udpscannoping)

                        count, ports = Scan.udpScan(ip, p1)

                        print("")
                        for p in ports:
                            print(p)
                        print("")

                        print(f"[+] {count} ports close !")

            
            elif(cont == 2):
                p1 = int(ports[0])
                p2 = int(ports[1])

                if(p1 > p2):
                    print("[-] out of range")

                else:
                    # Com output 
                    if(args.output):
                        # TCP scan com ping e output 
                        if(args.tcpscan):
                            check = Utils.checkIp(args.tcpscan)

                            if(check == True):
                                ip = args.tcpscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.tcpscan)

                            check = Scan.ping(ip)
                            file = open(args.output, "a")

                            if(check == True):
                                count, ports = Scan.tcpScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                    file.write(p)
                                print("")


                                file.close()
                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()
                        
                        # Banner scan com ping e output
                        elif(args.bannerscan):
                            check = Utils.checkIp(args.bannerscan)

                            if(check == True):
                                ip = args.bannerscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.bannerscan)

                            check = Scan.ping(ip)
                            file = open(args.output, "a")

                            if(check == True):
                                count, ports = Scan.tcpScanBanner(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                    file.write(p)
                                print("")

                                file.close()
                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()

                        # syn scan com ping e output 
                        elif(args.synscan):
                            check = Utils.checkIp(args.synscan)

                            if(check == True):
                                ip = args.synscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.synscan)

                            check = Scan.ping(ip)
                            file = open(args.output, "a")

                            if(check == True):
                                count, ports = Scan.synScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                    file.write(p)
                                print("")

                                file.close()
                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()

                        # Udp scan com ping e output
                        elif(args.udpscan):
                            check = Utils.checkIp(args.udpscan)

                            if(check == True):
                                ip = args.udpscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.udpscan)

                            check = Scan.ping(ip)
                            file = open(args.output, "a")

                            if(check == True):
                                count, ports = Scan.udpScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                    file.write(p)
                                print("")

                                file.close()
                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()



                        # TCP scan sem ping com output 
                        elif(args.tcpscannoping):
                            check = Utils.checkIp(args.tcpscannoping)

                            if(check == True):
                                ip = args.tcpscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.tcpscannoping)

                            file = open(args.output, "a")

                            count, ports = Scan.tcpScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")


                        # Banner scan sem ping com output 
                        elif(args.bannerscannoping):
                            check = Utils.checkIp(args.bannerscannoping)

                            if(check == True):
                                ip = args.bannerscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.bannerscannoping)

                            file = open(args.output, "a")

                            count, ports = Scan.tcpScanBanner(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")

                        # syn scan sem ping e output 
                        elif(args.synscannoping):
                            check = Utils.checkIp(args.synscannoping)

                            if(check == True):
                                ip = args.synscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.synscannoping)

                            file = open(args.output, "a")

                            count, ports = Scan.synScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")

                        # udp scan sem ping e output
                        elif(args.udpscannoping):
                            check = Utils.checkIp(args.udpscannoping)

                            if(check == True):
                                ip = args.udpscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.udpscannoping)

                            file = open(args.output, "a")

                            count, ports = Scan.udpScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                                file.write(p)
                            print("")

                            file.close()
                            print(f"[+] {count} ports close !")


                    else:
                        # TCP scan com ping sem output 
                        if(args.tcpscan):
                            check = Utils.checkIp(args.tcpscan)

                            if(check == True):
                                ip = args.tcpscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.tcpscan)

                            check = Scan.ping(ip)

                            if(check == True):
                                count, ports = Scan.tcpScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                print("")

                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()
                        
                        # Banner scan com ping sem output
                        elif(args.bannerscan):
                            check = Utils.checkIp(args.bannerscan)

                            if(check == True):
                                ip = args.bannerscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.bannerscan)

                            check = Scan.ping(ip)

                            if(check == True):
                                count, ports = Scan.tcpScanBanner(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                print("")

                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()

                        # syn scan com ping sem output 
                        elif(args.synscan):
                            check = Utils.checkIp(args.synscan)

                            if(check == True):
                                ip = args.synscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.synscan)

                            check = Scan.ping(ip)

                            if(check == True):
                                count, ports = Scan.synScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                print("")

                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()

                        # Udp scan com ping sem output
                        elif(args.udpscan):
                            check = Utils.checkIp(args.udpscan)

                            if(check == True):
                                ip = args.udpscan

                            elif(check == False):
                                ip = socket.gethostbyname(args.udpscan)

                            check = Scan.ping(ip)

                            if(check == True):
                                count, ports = Scan.udpScan(ip, p1, p2+1)

                                print("")
                                for p in ports:
                                    print(p)
                                print("")

                                print(f"[+] {count} ports close !")
                                
                            else:
                                exit()



                        # TCP scan sem ping sem output 
                        elif(args.tcpscannoping):
                            check = Utils.checkIp(args.tcpscannoping)

                            if(check == True):
                                ip = args.tcpscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.tcpscannoping)

                            count, ports = Scan.tcpScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")


                        # Banner scan sem ping sem output 
                        elif(args.bannerscannoping):
                            check = Utils.checkIp(args.bannerscannoping)

                            if(check == True):
                                ip = args.bannerscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.bannerscannoping)

                            count, ports = Scan.tcpScanBanner(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")

                        # syn scan sem ping sem output 
                        elif(args.synscannoping):
                            check = Utils.checkIp(args.synscannoping)

                            if(check == True):
                                ip = args.synscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.synscannoping)

                            count, ports = Scan.synScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")

                        # udp scan sem ping sem output
                        elif(args.udpscannoping):
                            check = Utils.checkIp(args.udpscannoping)

                            if(check == True):
                                ip = args.udpscannoping

                            elif(check == False):
                                ip = socket.gethostbyname(args.udpscannoping)

                            count, ports = Scan.udpScan(ip, p1, p2+1)

                            print("")
                            for p in ports:
                                print(p)
                            print("")

                            print(f"[+] {count} ports close !")
    

    except KeyboardInterrupt:
        print("Bye Bye")

    except PermissionError:
        print("[-] you are not root user, please type the command 'sudo'")

    
    #except Exception as err:
    #    print("an error occurred ")
    #    print("")
    #    print(err)


main(args)