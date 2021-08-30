

-sP --pingscan: performs a pingscan: -sP 192.168.0.1
-sT --tcpscan: does a tcpscan: -sT 192.168.0.1
-sV --bannerscan: does a tcpScan with banner grabbing: -sV 192.168.0.1
-sS --synscan: performs a synscan: -sS 192.168.0.1
-sU --udpscan: perform a udpscan: -sU 192.168.0.1

-sTn --tcpscannoping: does a tcpscan without the initial ping: -sTn 192.168.0.1
-sVn --bannerscannoping: does a tcpScan with banner grabbing without the initial ping: -sV 192.168.0.1
-sSn --synscannoping: performs a synscan without the initial ping: -sS 192.168.0.1
-sUn --udpscannoping: perform a udpscan without the initial ping: -sU 192.168.0.1

-p --ports: sets the ports for the scan: -p All, -p Low, -p High, -p 10, -p 40-60
-O --output: creates an output file with the scan information: -O filename.txt


Modo de execução: 
    ./Pmapper -sS 192.168.0.1 -p all
    ./Pmapper -sT 192.168.0.1 -p low -o output.txt
    ./Pmapper -sV 192.168.0.1 -p 40-70
    ./Pmapper -sTn 192.168.0.1 -p 70
    ./Pmapper -sSn 192.168.0.1 -p low -o output.txt
    
new release soon.....
