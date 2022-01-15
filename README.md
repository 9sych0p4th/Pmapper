

-sP --pingscan: performs a pingscan: -sP 192.168.0.1 <br>
-sT --tcpscan: does a tcpscan: -sT 192.168.0.1<br>
-sV --bannerscan: does a tcpScan with banner grabbing: -sV 192.168.0.1<br>
-sS --synscan: performs a synscan: -sS 192.168.0.1<br>
-sU --udpscan: perform a udpscan: -sU 192.168.0.1<br>

-sTn --tcpscannoping: does a tcpscan without the initial ping: -sTn 192.168.0.1<br>
-sVn --bannerscannoping: does a tcpScan with banner grabbing without the initial ping: -sV 192.168.0.1<br>
-sSn --synscannoping: performs a synscan without the initial ping: -sS 192.168.0.1<br>
-sUn --udpscannoping: perform a udpscan without the initial ping: -sU 192.168.0.1<br>

-p --ports: sets the ports for the scan: -p All, -p Low, -p High, -p 10, -p 40-60<br>
-O --output: creates an output file with the scan information: -O filename.txt<br>


Modo de execução: <br>
    ./Pmapper -sS 192.168.0.1 -p all<br>
    ./Pmapper -sT 192.168.0.1 -p low -o output.txt<br>
    ./Pmapper -sV 192.168.0.1 -p 40-70<br>
    ./Pmapper -sTn 192.168.0.1 -p 70<br>
    ./Pmapper -sSn 192.168.0.1 -p low -o output.txt<br>
    
new release soon.....<br>
