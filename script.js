/**
 * NetTriage — Network Traffic Triage Tool
 * 
 * 100% Client-Side In-Browser Analysis
 * Educational SOC Analyst Training Tool
 */

(function () {
  'use strict';

  // -------------------------------------------------------------
  // Embedded Demo Datasets (Guarantees zero-CORS offline execution)
  // -------------------------------------------------------------
  const DEMO_SAMPLES = {
    normal: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","0.0.0.0","255.255.255.255","DHCP","342","DHCP Discover - Transaction ID 0x39a1b2c3"
"2","0.012540","192.168.1.1","192.168.1.105","DHCP","342","DHCP Offer    - Transaction ID 0x39a1b2c3"
"3","0.015210","0.0.0.0","255.255.255.255","DHCP","342","DHCP Request  - Transaction ID 0x39a1b2c3"
"4","0.024500","192.168.1.1","192.168.1.105","DHCP","342","DHCP ACK      - Transaction ID 0x39a1b2c3"
"5","0.105420","192.168.1.105","192.168.1.1","DNS","74","Standard query 0x12a4 A gateway.local"
"6","0.108920","192.168.1.1","192.168.1.105","DNS","90","Standard query response 0x12a4 A 192.168.1.1"
"7","0.210450","192.168.1.105","192.168.1.1","DNS","78","Standard query 0x24b1 A time.cloudflare.com"
"8","0.235120","192.168.1.1","192.168.1.105","DNS","94","Standard query response 0x24b1 A 162.159.200.1"
"9","0.312000","192.168.1.105","162.159.200.1","NTP","90","NTP Version 4, client"
"10","0.345100","162.159.200.1","192.168.1.105","NTP","90","NTP Version 4, server"
"11","1.050200","192.168.1.105","192.168.1.1","DNS","72","Standard query 0x38e2 A example.org"
"12","1.074300","192.168.1.1","192.168.1.105","DNS","88","Standard query response 0x38e2 A 93.184.216.34"
"13","1.120000","192.168.1.105","93.184.216.34","TCP","66","54210 → 80 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"14","1.145000","93.184.216.34","192.168.1.105","TCP","66","80 → 54210 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
"15","1.145200","192.168.1.105","93.184.216.34","TCP","54","54210 → 80 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"16","1.150000","192.168.1.105","93.184.216.34","HTTP","145","GET /index.html HTTP/1.1"
"17","1.175000","93.184.216.34","192.168.1.105","TCP","54","80 → 54210 [ACK] Seq=1 Ack=92 Win=65535 Len=0"
"18","1.182000","93.184.216.34","192.168.1.105","HTTP","482","HTTP/1.1 200 OK (text/html)"
"19","1.182500","192.168.1.105","93.184.216.34","TCP","54","54210 → 80 [ACK] Seq=92 Ack=429 Win=64240 Len=0"
"20","1.300000","192.168.1.105","93.184.216.34","TCP","54","54210 → 80 [FIN, ACK] Seq=92 Ack=429 Win=64240 Len=0"
"21","1.325000","93.184.216.34","192.168.1.105","TCP","54","80 → 54210 [FIN, ACK] Seq=429 Ack=93 Win=65535 Len=0"
"22","1.325200","192.168.1.105","93.184.216.34","TCP","54","54210 → 80 [ACK] Seq=93 Ack=430 Win=64240 Len=0"
"23","2.010000","192.168.1.102","192.168.1.1","DNS","76","Standard query 0x77c1 A secure.company.internal"
"24","2.015000","192.168.1.1","192.168.1.102","DNS","92","Standard query response 0x77c1 A 192.168.1.200"
"25","2.025000","192.168.1.102","192.168.1.200","TCP","66","49812 → 443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"26","2.028000","192.168.1.200","192.168.1.102","TCP","66","443 → 49812 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
"27","2.028200","192.168.1.102","192.168.1.200","TCP","54","49812 → 443 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"28","2.035000","192.168.1.102","192.168.1.200","TLSv1.3","517","Client Hello"
"29","2.042000","192.168.1.200","192.168.1.102","TLSv1.3","1420","Server Hello, Change Cipher Spec, Application Data"
"30","2.042500","192.168.1.102","192.168.1.200","TCP","54","49812 → 443 [ACK] Seq=464 Ack=1367 Win=64240 Len=0"
"31","3.100000","192.168.1.1","192.168.1.255","ARP","60","Who has 192.168.1.108? Tell 192.168.1.1"
"32","4.500000","192.168.1.105","192.168.1.1","ICMP","98","Echo (ping) request  id=0x0001, seq=1/256, ttl=64"
"33","4.501500","192.168.1.1","192.168.1.105","ICMP","98","Echo (ping) reply    id=0x0001, seq=1/256, ttl=64"
"34","5.500000","192.168.1.105","192.168.1.1","ICMP","98","Echo (ping) request  id=0x0001, seq=2/512, ttl=64"
"35","5.501200","192.168.1.1","192.168.1.105","ICMP","98","Echo (ping) reply    id=0x0001, seq=2/512, ttl=64"`,

    highVolume: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","192.168.1.10","192.168.1.1","DNS","74","Standard query 0x1100 A backup.corp.local"
"2","0.002100","192.168.1.1","192.168.1.10","DNS","90","Standard query response 0x1100 A 192.168.1.50"
"3","0.010000","192.168.1.55","192.168.1.50","TCP","66","41200 → 8443 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"4","0.011200","192.168.1.50","192.168.1.55","TCP","66","8443 → 41200 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
"5","0.011300","192.168.1.55","192.168.1.50","TCP","54","41200 → 8443 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"6","0.015000","192.168.1.55","192.168.1.50","TLSv1.3","517","Client Hello"
"7","0.018000","192.168.1.50","192.168.1.55","TLSv1.3","1420","Server Hello, Change Cipher Spec"
"8","0.018200","192.168.1.55","192.168.1.50","TCP","54","41200 → 8443 [ACK] Seq=464 Ack=1367 Win=64240 Len=0"
"9","0.020000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #1]"
"10","0.020500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #2]"
"11","0.021000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #3]"
"12","0.021500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #4]"
"13","0.022000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #5]"
"14","0.022500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #6]"
"15","0.023000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #7]"
"16","0.023500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #8]"
"17","0.024000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #9]"
"18","0.024500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #10]"
"19","0.025000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #11]"
"20","0.025500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #12]"
"21","0.026000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #13]"
"22","0.026500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #14]"
"23","0.027000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #15]"
"24","0.027500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #16]"
"25","0.028000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #17]"
"26","0.028500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #18]"
"27","0.029000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #19]"
"28","0.029500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #20]"
"29","0.030000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #21]"
"30","0.030500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #22]"
"31","0.031000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #23]"
"32","0.031500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #24]"
"33","0.032000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #25]"
"34","0.032500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #26]"
"35","0.033000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #27]"
"36","0.033500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #28]"
"37","0.034000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #29]"
"38","0.034500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #30]"
"39","0.035000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #31]"
"40","0.035500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #32]"
"41","0.036000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #33]"
"42","0.036500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #34]"
"43","0.037000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #35]"
"44","0.037500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #36]"
"45","0.038000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #37]"
"46","0.038500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #38]"
"47","0.039000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #39]"
"48","0.039500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #40]"
"49","0.040000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #41]"
"50","0.040500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #42]"
"51","0.041000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #43]"
"52","0.041500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #44]"
"53","0.042000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #45]"
"54","0.042500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #46]"
"55","0.043000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #47]"
"56","0.043500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #48]"
"57","0.044000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #49]"
"58","0.044500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #50]"
"59","0.045000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #51]"
"60","0.045500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #52]"
"61","0.046000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #53]"
"62","0.046500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #54]"
"63","0.047000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #55]"
"64","0.047500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #56]"
"65","0.048000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #57]"
"66","0.048500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #58]"
"67","0.049000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #59]"
"68","0.049500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #60]"
"69","0.050000","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #61]"
"70","0.050500","192.168.1.55","192.168.1.50","TLSv1.3","1514","Application Data [Backup Block #62]"
"71","0.051000","192.168.1.55","192.168.1.50","TCP","54","41200 → 8443 [FIN, ACK] Seq=91240 Ack=1367 Win=64240 Len=0"
"72","0.052000","192.168.1.50","192.168.1.55","TCP","54","8443 → 41200 [ACK] Seq=1367 Ack=91241 Win=65535 Len=0"`,

    mixedLab: `"No.","Time","Source","Destination","Protocol","Length","Info"
"1","0.000000","10.0.0.15","10.0.0.1","DNS","74","Standard query 0x1010 A fileserver.corp.local"
"2","0.001200","10.0.0.1","10.0.0.15","DNS","90","Standard query response 0x1010 A 10.0.0.20"
"3","0.005000","10.0.0.15","10.0.0.20","TCP","66","51234 → 445 [SYN] Seq=0 Win=64240 Len=0 MSS=1460"
"4","0.006100","10.0.0.20","10.0.0.15","TCP","66","445 → 51234 [SYN, ACK] Seq=0 Ack=1 Win=65535 Len=0"
"5","0.006200","10.0.0.15","10.0.0.20","TCP","54","51234 → 445 [ACK] Seq=1 Ack=1 Win=64240 Len=0"
"6","0.010000","10.0.0.15","10.0.0.20","SMB2","182","Negotiate Protocol Request"
"7","0.012000","10.0.0.20","10.0.0.15","SMB2","268","Negotiate Protocol Response"
"8","0.050000","10.0.0.99","10.0.0.2","TCP","66","49152 → 21 [SYN] Seq=0 Win=1024 Len=0"
"9","0.051000","10.0.0.99","10.0.0.3","TCP","66","49153 → 22 [SYN] Seq=0 Win=1024 Len=0"
"10","0.052000","10.0.0.99","10.0.0.4","TCP","66","49154 → 23 [SYN] Seq=0 Win=1024 Len=0"
"11","0.053000","10.0.0.99","10.0.0.5","TCP","66","49155 → 25 [SYN] Seq=0 Win=1024 Len=0"
"12","0.054000","10.0.0.99","10.0.0.6","TCP","66","49156 → 53 [SYN] Seq=0 Win=1024 Len=0"
"13","0.055000","10.0.0.99","10.0.0.7","TCP","66","49157 → 80 [SYN] Seq=0 Win=1024 Len=0"
"14","0.056000","10.0.0.99","10.0.0.8","TCP","66","49158 → 110 [SYN] Seq=0 Win=1024 Len=0"
"15","0.057000","10.0.0.99","10.0.0.9","TCP","66","49159 → 135 [SYN] Seq=0 Win=1024 Len=0"
"16","0.058000","10.0.0.99","10.0.0.10","TCP","66","49160 → 139 [SYN] Seq=0 Win=1024 Len=0"
"17","0.059000","10.0.0.99","10.0.0.11","TCP","66","49161 → 143 [SYN] Seq=0 Win=1024 Len=0"
"18","0.060000","10.0.0.99","10.0.0.12","TCP","66","49162 → 443 [SYN] Seq=0 Win=1024 Len=0"
"19","0.061000","10.0.0.99","10.0.0.13","TCP","66","49163 → 445 [SYN] Seq=0 Win=1024 Len=0"
"20","0.062000","10.0.0.99","10.0.0.14","TCP","66","49164 → 3389 [SYN] Seq=0 Win=1024 Len=0"
"21","0.063000","10.0.0.99","10.0.0.15","TCP","66","49165 → 8080 [SYN] Seq=0 Win=1024 Len=0"
"22","0.100000","10.0.0.77","10.0.0.1","ICMP","98","Echo (ping) request  id=0x1111, seq=1/256, ttl=64"
"23","0.101000","10.0.0.77","10.0.0.2","ICMP","98","Echo (ping) request  id=0x1111, seq=2/256, ttl=64"
"24","0.102000","10.0.0.77","10.0.0.3","ICMP","98","Echo (ping) request  id=0x1111, seq=3/256, ttl=64"
"25","0.103000","10.0.0.77","10.0.0.4","ICMP","98","Echo (ping) request  id=0x1111, seq=4/256, ttl=64"
"26","0.104000","10.0.0.77","10.0.0.5","ICMP","98","Echo (ping) request  id=0x1111, seq=5/256, ttl=64"
"27","0.105000","10.0.0.77","10.0.0.6","ICMP","98","Echo (ping) request  id=0x1111, seq=6/256, ttl=64"
"28","0.106000","10.0.0.77","10.0.0.7","ICMP","98","Echo (ping) request  id=0x1111, seq=7/256, ttl=64"
"29","0.107000","10.0.0.77","10.0.0.8","ICMP","98","Echo (ping) request  id=0x1111, seq=8/256, ttl=64"
"30","0.108000","10.0.0.77","10.0.0.9","ICMP","98","Echo (ping) request  id=0x1111, seq=9/256, ttl=64"
"31","0.109000","10.0.0.77","10.0.0.10","ICMP","98","Echo (ping) request  id=0x1111, seq=10/256, ttl=64"
"32","0.110000","10.0.0.77","10.0.0.11","ICMP","98","Echo (ping) request  id=0x1111, seq=11/256, ttl=64"
"33","0.111000","10.0.0.77","10.0.0.12","ICMP","98","Echo (ping) request  id=0x1111, seq=12/256, ttl=64"
"34","0.112000","10.0.0.77","10.0.0.13","ICMP","98","Echo (ping) request  id=0x1111, seq=13/256, ttl=64"
"35","0.113000","10.0.0.77","10.0.0.14","ICMP","98","Echo (ping) request  id=0x1111, seq=14/256, ttl=64"
"36","0.114000","10.0.0.77","10.0.0.15","ICMP","98","Echo (ping) request  id=0x1111, seq=15/256, ttl=64"
"37","0.115000","10.0.0.77","10.0.0.16","ICMP","98","Echo (ping) request  id=0x1111, seq=16/256, ttl=64"
"38","0.116000","10.0.0.77","10.0.0.17","ICMP","98","Echo (ping) request  id=0x1111, seq=17/256, ttl=64"
"39","0.117000","10.0.0.77","10.0.0.18","ICMP","98","Echo (ping) request  id=0x1111, seq=18/256, ttl=64"
"40","0.118000","10.0.0.77","10.0.0.19","ICMP","98","Echo (ping) request  id=0x1111, seq=19/256, ttl=64"
"41","0.119000","10.0.0.77","10.0.0.20","ICMP","98","Echo (ping) request  id=0x1111, seq=20/256, ttl=64"
"42","0.120000","10.0.0.77","10.0.0.21","ICMP","98","Echo (ping) request  id=0x1111, seq=21/256, ttl=64"
"43","0.121000","10.0.0.77","10.0.0.22","ICMP","98","Echo (ping) request  id=0x1111, seq=22/256, ttl=64"
"44","0.122000","10.0.0.77","10.0.0.23","ICMP","98","Echo (ping) request  id=0x1111, seq=23/256, ttl=64"
"45","0.123000","10.0.0.77","10.0.0.24","ICMP","98","Echo (ping) request  id=0x1111, seq=24/256, ttl=64"
"46","0.124000","10.0.0.77","10.0.0.25","ICMP","98","Echo (ping) request  id=0x1111, seq=25/256, ttl=64"
"47","0.125000","10.0.0.77","10.0.0.26","ICMP","98","Echo (ping) request  id=0x1111, seq=26/256, ttl=64"
"48","0.126000","10.0.0.77","10.0.0.27","ICMP","98","Echo (ping) request  id=0x1111, seq=27/256, ttl=64"
"49","0.127000","10.0.0.77","10.0.0.28","ICMP","98","Echo (ping) request  id=0x1111, seq=28/256, ttl=64"
"50","0.128000","10.0.0.77","10.0.0.29","ICMP","98","Echo (ping) request  id=0x1111, seq=29/256, ttl=64"
"51","0.129000","10.0.0.77","10.0.0.30","ICMP","98","Echo (ping) request  id=0x1111, seq=30/256, ttl=64"
"52","0.130000","10.0.0.77","10.0.0.31","ICMP","98","Echo (ping) request  id=0x1111, seq=31/256, ttl=64"
"53","0.131000","10.0.0.77","10.0.0.32","ICMP","98","Echo (ping) request  id=0x1111, seq=32/256, ttl=64"
"54","0.132000","10.0.0.77","10.0.0.33","ICMP","98","Echo (ping) request  id=0x1111, seq=33/256, ttl=64"
"55","0.133000","10.0.0.77","10.0.0.34","ICMP","98","Echo (ping) request  id=0x1111, seq=34/256, ttl=64"
"56","0.134000","10.0.0.77","10.0.0.35","ICMP","98","Echo (ping) request  id=0x1111, seq=35/256, ttl=64"
"57","0.200000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 1"
"58","0.201000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 2"
"59","0.202000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 3"
"60","0.203000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 4"
"61","0.204000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 5"
"62","0.205000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 6"
"63","0.206000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 7"
"64","0.207000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 8"
"65","0.208000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 9"
"66","0.209000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 10"
"67","0.210000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 11"
"68","0.211000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 12"
"69","0.212000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 13"
"70","0.213000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 14"
"71","0.214000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 15"
"72","0.215000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 16"
"73","0.216000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 17"
"74","0.217000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 18"
"75","0.218000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 19"
"76","0.219000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 20"
"77","0.220000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 21"
"78","0.221000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 22"
"79","0.222000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 23"
"80","0.223000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 24"
"81","0.224000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 25"
"82","0.225000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 26"
"83","0.226000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 27"
"84","0.227000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 28"
"85","0.228000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 29"
"86","0.229000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 30"
"87","0.230000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 31"
"88","0.231000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 32"
"89","0.232000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 33"
"90","0.233000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 34"
"91","0.234000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 35"
"92","0.235000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 36"
"93","0.236000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 37"
"94","0.237000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 38"
"95","0.238000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 39"
"96","0.239000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 40"
"97","0.240000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 41"
"98","0.241000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 42"
"99","0.242000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 43"
"100","0.243000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 44"
"101","0.244000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 45"
"102","0.245000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 46"
"103","0.246000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 47"
"104","0.247000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 48"
"105","0.248000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 49"
"106","0.249000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 50"
"107","0.250000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 51"
"108","0.251000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 52"
"109","0.252000","192.168.1.100","192.168.1.200","TCP","1420","50001 → 9000 [ACK] PUSH Data chunk 53"
"110","0.253000","192.168.1.100","192.168.1.200","TCP","54","50001 → 9000 [FIN, ACK] Seq=76680 Ack=1 Win=64240 Len=0"
"111","0.300000","172.16.5.10","172.16.5.1","DNS","74","Standard query 0xa001 A api.update-service.internal"
"112","0.301500","172.16.5.1","172.16.5.10","DNS","90","Standard query response 0xa001 A 172.16.5.50"
"113","0.305000","172.16.5.10","172.16.5.50","HTTP","168","GET /v1/health HTTP/1.1"
"114","0.309000","172.16.5.50","172.16.5.10","HTTP","212","HTTP/1.1 200 OK (application/json)"`
  };

  // -------------------------------------------------------------
  // Default Settings & State
  // -------------------------------------------------------------
  const DEFAULT_THRESHOLDS = {
    highVolume: 50,
    uniqueDest: 10,
    uniquePorts: 10,
    icmp: 30,
    dns: 30,
    repeatedPair: 40,
    tcpSyn: 20
  };

  let currentThresholds = { ...DEFAULT_THRESHOLDS };

  let currentPackets = [];
  let currentFileName = '';
  let isDemoData = false;
  let allAlerts = [];

  // -------------------------------------------------------------
  // DOM Elements Cache
  // -------------------------------------------------------------
  const dropZone = document.getElementById('dropZone');
  const fileInput = document.getElementById('fileInput');
  const btnDemoNormal = document.getElementById('btnDemoNormal');
  const btnDemoHighVolume = document.getElementById('btnDemoHighVolume');
  const btnDemoMixedLab = document.getElementById('btnDemoMixedLab');
  const btnClearData = document.getElementById('btnClearData');

  const fileStatusBar = document.getElementById('fileStatusBar');
  const demoDataBadge = document.getElementById('demoDataBadge');
  const statusFileName = document.getElementById('statusFileName');
  const statusPacketCount = document.getElementById('statusPacketCount');
  const statusParseState = document.getElementById('statusParseState');
  const missingFieldsWarning = document.getElementById('missingFieldsWarning');

  const settingsToggle = document.getElementById('settingsToggle');
  const settingsBody = document.getElementById('settingsBody');
  const btnApplyThresholds = document.getElementById('btnApplyThresholds');
  const btnResetThresholds = document.getElementById('btnResetThresholds');

  const inputHighVolume = document.getElementById('threshHighVolume');
  const inputUniqueDest = document.getElementById('threshUniqueDest');
  const inputUniquePorts = document.getElementById('threshUniquePorts');
  const inputIcmp = document.getElementById('threshIcmp');
  const inputDns = document.getElementById('threshDns');
  const inputRepeatedPair = document.getElementById('threshRepeatedPair');
  const inputTcpSyn = document.getElementById('threshTcpSyn');

  const emptyState = document.getElementById('emptyState');
  const resultsContainer = document.getElementById('resultsContainer');

  const scoreValue = document.getElementById('scoreValue');
  const scoreBadge = document.getElementById('scoreBadge');
  const scoreBreakdownList = document.getElementById('scoreBreakdownList');

  const kpiTotalPackets = document.getElementById('kpiTotalPackets');
  const kpiSourceHosts = document.getElementById('kpiSourceHosts');
  const kpiDestHosts = document.getElementById('kpiDestHosts');
  const kpiTopSource = document.getElementById('kpiTopSource');
  const kpiTopSourceCount = document.getElementById('kpiTopSourceCount');
  const kpiTopDest = document.getElementById('kpiTopDest');
  const kpiTopDestCount = document.getElementById('kpiTopDestCount');
  const kpiTopProtocol = document.getElementById('kpiTopProtocol');
  const kpiAvgLength = document.getElementById('kpiAvgLength');

  const alertsCountBadge = document.getElementById('alertsCountBadge');
  const alertsContainer = document.getElementById('alertsContainer');

  const filterSeverity = document.getElementById('filterSeverity');
  const filterSourceIp = document.getElementById('filterSourceIp');
  const filterDestIp = document.getElementById('filterDestIp');
  const filterSearchText = document.getElementById('filterSearchText');
  const btnResetFilters = document.getElementById('btnResetFilters');

  const topSourcesBody = document.getElementById('topSourcesBody');
  const topDestinationsBody = document.getElementById('topDestinationsBody');
  const protocolBarsContainer = document.getElementById('protocolBarsContainer');

  const rawPacketsToggle = document.getElementById('rawPacketsToggle');
  const rawPacketsBody = document.getElementById('rawPacketsBody');
  const rawPacketCountLabel = document.getElementById('rawPacketCountLabel');
  const packetSearchInput = document.getElementById('packetSearchInput');
  const packetFilterMatchCount = document.getElementById('packetFilterMatchCount');
  const packetsTableBody = document.getElementById('packetsTableBody');

  // -------------------------------------------------------------
  // HTML Sanitization & Safety Helper (Prevent DOM XSS)
  // -------------------------------------------------------------
  function escapeHTML(str) {
    if (str === null || str === undefined) return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // -------------------------------------------------------------
  // RFC 4180 Robust CSV Parser
  // -------------------------------------------------------------
  function parseCSV(text) {
    const rows = [];
    let currentRow = [];
    let currentField = '';
    let inQuotes = false;

    // Normalize newlines
    const len = text.length;
    for (let i = 0; i < len; i++) {
      const char = text[i];
      const nextChar = text[i + 1];

      if (inQuotes) {
        if (char === '"') {
          if (nextChar === '"') {
            // Escaped quote
            currentField += '"';
            i++;
          } else {
            // End of quoted field
            inQuotes = false;
          }
        } else {
          currentField += char;
        }
      } else {
        if (char === '"') {
          inQuotes = true;
        } else if (char === ',') {
          currentRow.push(currentField);
          currentField = '';
        } else if (char === '\r') {
          if (nextChar === '\n') {
            i++;
          }
          currentRow.push(currentField);
          rows.push(currentRow);
          currentRow = [];
          currentField = '';
        } else if (char === '\n') {
          currentRow.push(currentField);
          rows.push(currentRow);
          currentRow = [];
          currentField = '';
        } else {
          currentField += char;
        }
      }
    }

    if (currentField !== '' || currentRow.length > 0) {
      currentRow.push(currentField);
      rows.push(currentRow);
    }

    return rows;
  }

  // Column Matcher using known Wireshark aliases
  function identifyColumns(headerRow) {
    const colMap = {
      no: -1,
      time: -1,
      source: -1,
      destination: -1,
      protocol: -1,
      length: -1,
      info: -1
    };

    const aliases = {
      no: ['no.', 'no', 'number', 'frame.number', 'packet_number', '#'],
      time: ['time', 'timestamp', 'frame.time_relative', 'frame.time', 'time_delta'],
      source: ['source', 'source ip', 'src', 'ip.src', 'ipv6.src', 'source address', 'src_ip', 'ip_src'],
      destination: ['destination', 'destination ip', 'dst', 'ip.dst', 'ipv6.dst', 'destination address', 'dst_ip', 'ip_dst'],
      protocol: ['protocol', 'proto', '_ws.col.protocol', 'ip.proto', 'transport'],
      length: ['length', 'len', 'frame.len', 'packet length', 'bytes'],
      info: ['info', 'description', 'summary', '_ws.col.info', 'packet info']
    };

    headerRow.forEach((col, idx) => {
      const cleaned = col.trim().toLowerCase();
      for (const [key, patterns] of Object.entries(aliases)) {
        if (colMap[key] === -1 && patterns.includes(cleaned)) {
          colMap[key] = idx;
        }
      }
    });

    return colMap;
  }

  // Transform raw CSV rows into normalized packet objects
  function processCSVData(csvText, fileName, demoFlag = false) {
    const parsedRows = parseCSV(csvText);
    if (!parsedRows || parsedRows.length < 2) {
      showErrorState(fileName, 'The uploaded CSV file is empty or does not contain data rows.');
      return;
    }

    const header = parsedRows[0];
    const colMap = identifyColumns(header);

    const missingAlerts = [];
    if (colMap.source === -1) {
      missingAlerts.push('This CSV does not appear to contain a recognisable "Source" address column.');
    }
    if (colMap.destination === -1) {
      missingAlerts.push('This CSV does not appear to contain a recognisable "Destination" address column.');
    }
    if (colMap.protocol === -1) {
      missingAlerts.push('This CSV is missing a "Protocol" column (traffic will be grouped as "Unknown").');
    }

    const packets = [];
    for (let i = 1; i < parsedRows.length; i++) {
      const row = parsedRows[i];
      if (row.length === 1 && row[0].trim() === '') continue; // Skip blank line

      const no = colMap.no !== -1 && row[colMap.no] ? row[colMap.no].trim() : String(i);
      const time = colMap.time !== -1 && row[colMap.time] ? row[colMap.time].trim() : '0.000';
      const source = colMap.source !== -1 && row[colMap.source] ? row[colMap.source].trim() : 'Unknown';
      const destination = colMap.destination !== -1 && row[colMap.destination] ? row[colMap.destination].trim() : 'Unknown';
      const protocol = colMap.protocol !== -1 && row[colMap.protocol] ? row[colMap.protocol].trim().toUpperCase() : 'OTHER';
      
      let length = 0;
      if (colMap.length !== -1 && row[colMap.length]) {
        const parsedLen = parseInt(row[colMap.length].trim(), 10);
        if (!isNaN(parsedLen)) length = parsedLen;
      }

      const info = colMap.info !== -1 && row[colMap.info] ? row[colMap.info].trim() : '';

      packets.push({
        no,
        time,
        source,
        destination,
        protocol,
        length,
        info
      });
    }

    if (packets.length === 0) {
      showErrorState(fileName, 'No valid packet records were parsed from this CSV.');
      return;
    }

    currentPackets = packets;
    currentFileName = fileName;
    isDemoData = demoFlag;

    updateFileStatusBar(fileName, packets.length, missingAlerts, demoFlag);
    runTriageAnalysis();
  }

  function showErrorState(fileName, message) {
    fileStatusBar.style.display = 'flex';
    demoDataBadge.style.display = 'none';
    statusFileName.textContent = fileName || 'Unknown File';
    statusPacketCount.textContent = '0';
    statusParseState.className = 'status-tag warning';
    statusParseState.textContent = 'Parsing Failed';
    missingFieldsWarning.style.display = 'block';
    missingFieldsWarning.textContent = message;

    emptyState.style.display = 'block';
    resultsContainer.style.display = 'none';
    btnClearData.style.display = 'none';
  }

  function updateFileStatusBar(fileName, packetCount, missingAlerts, demoFlag) {
    fileStatusBar.style.display = 'flex';
    statusFileName.textContent = fileName;
    statusPacketCount.textContent = packetCount.toLocaleString();

    if (demoFlag) {
      demoDataBadge.style.display = 'inline-block';
    } else {
      demoDataBadge.style.display = 'none';
    }

    if (missingAlerts.length > 0) {
      statusParseState.className = 'status-tag warning';
      statusParseState.textContent = 'Parsed with Warnings';
      missingFieldsWarning.style.display = 'block';
      missingFieldsWarning.innerHTML = missingAlerts.map(msg => `<div>• ${escapeHTML(msg)}</div>`).join('');
    } else {
      statusParseState.className = 'status-tag success';
      statusParseState.textContent = 'Parsed Successfully';
      missingFieldsWarning.style.display = 'none';
      missingFieldsWarning.innerHTML = '';
    }

    emptyState.style.display = 'none';
    resultsContainer.style.display = 'block';
    btnClearData.style.display = 'inline-block';
  }

  // -------------------------------------------------------------
  // Destination Port Extractor (Best effort for Rule 3)
  // -------------------------------------------------------------
  function extractDestinationPort(infoStr) {
    if (!infoStr) return null;
    // Common Wireshark patterns in Info column:
    // "54210 → 80 [SYN]..."
    // "49812 > 443 [ACK]..."
    // "Port: 80" or "dstport=443"
    const arrowMatch = infoStr.match(/(?:→|>)\s*(\d{1,5})/);
    if (arrowMatch && arrowMatch[1]) {
      const port = parseInt(arrowMatch[1], 10);
      if (port > 0 && port <= 65535) return port;
    }

    const portMatch = infoStr.match(/(?:port|dstport|dport)[:=\s]+(\d{1,5})/i);
    if (portMatch && portMatch[1]) {
      const port = parseInt(portMatch[1], 10);
      if (port > 0 && port <= 65535) return port;
    }

    return null;
  }

  // -------------------------------------------------------------
  // Detection Rules Engine (Pure Rule-Based, 0% ML)
  // -------------------------------------------------------------
  function runTriageAnalysis() {
    if (!currentPackets || currentPackets.length === 0) return;

    // 1. Aggregations
    const sourceStats = new Map();     // src -> { count, dests: Set, dportsByDest: Map, icmp: 0, dns: 0, syn: 0 }
    const destCounts = new Map();      // dst -> count
    const pairCounts = new Map();      // "src -> dst" -> { count, src, dst, protocols: Map }
    const protocolCounts = new Map();  // proto -> count
    let totalLength = 0;
    let lengthCount = 0;

    for (let i = 0; i < currentPackets.length; i++) {
      const pkt = currentPackets[i];
      const src = pkt.source;
      const dst = pkt.destination;
      const proto = pkt.protocol || 'OTHER';

      if (pkt.length > 0) {
        totalLength += pkt.length;
        lengthCount++;
      }

      // Protocol Counts
      protocolCounts.set(proto, (protocolCounts.get(proto) || 0) + 1);

      // Destination Host Counts
      if (dst && dst !== 'Unknown') {
        destCounts.set(dst, (destCounts.get(dst) || 0) + 1);
      }

      // Source Host Stats
      if (src && src !== 'Unknown') {
        if (!sourceStats.has(src)) {
          sourceStats.set(src, {
            count: 0,
            dests: new Set(),
            dportsByDest: new Map(),
            icmp: 0,
            dns: 0,
            syn: 0
          });
        }
        const sEntry = sourceStats.get(src);
        sEntry.count++;

        if (dst && dst !== 'Unknown') {
          sEntry.dests.add(dst);

          // Port extraction for Rule 3
          const destPort = extractDestinationPort(pkt.info);
          if (destPort !== null) {
            if (!sEntry.dportsByDest.has(dst)) {
              sEntry.dportsByDest.set(dst, new Set());
            }
            sEntry.dportsByDest.get(dst).add(destPort);
          }
        }

        // ICMP Check (Rule 4)
        if (proto === 'ICMP' || proto === 'ICMPV6') {
          sEntry.icmp++;
        }

        // DNS Check (Rule 5)
        if (proto === 'DNS' || (pkt.info && pkt.info.includes('query'))) {
          sEntry.dns++;
        }

        // TCP SYN Check (Rule 7)
        if (proto === 'TCP' && pkt.info && (pkt.info.includes('[SYN]') || pkt.info.includes('SYN'))) {
          sEntry.syn++;
        }
      }

      // Pair Stats (Rule 6)
      if (src && dst && src !== 'Unknown' && dst !== 'Unknown') {
        const pairKey = `${src} → ${dst}`;
        if (!pairCounts.has(pairKey)) {
          pairCounts.set(pairKey, { count: 0, src, dst, protocols: new Map() });
        }
        const pEntry = pairCounts.get(pairKey);
        pEntry.count++;
        pEntry.protocols.set(proto, (pEntry.protocols.get(proto) || 0) + 1);
      }
    }

    // 2. Evaluation of Detection Rules
    const alerts = [];
    const scoreItems = [];

    // Helper: Find top protocol in pair
    function getTopProtocol(protoMap) {
      let topProto = 'N/A';
      let maxCount = -1;
      for (const [p, c] of protoMap.entries()) {
        if (c > maxCount) {
          maxCount = c;
          topProto = p;
        }
      }
      return topProto;
    }

    // RULE 1: High Packet Volume
    for (const [src, data] of sourceStats.entries()) {
      if (data.count > currentThresholds.highVolume) {
        alerts.push({
          ruleId: 'RULE-1',
          name: 'High Packet Volume',
          severity: 'Medium',
          source: src,
          destination: 'Various',
          observed: `${data.count} packets sent`,
          threshold: `>${currentThresholds.highVolume} packets`,
          whyMatters: 'A host generating significantly more traffic than expected may warrant investigation. Sudden volume spikes can reflect large automated operations, active exfiltration, network scanning, or local software errors.',
          benignExplanations: [
            'Legitimate large file backup or operating system updates',
            'Internal network file transfers (e.g., SMB/NFS transfers)',
            'Media streaming or video conferencing sessions',
            'Automated database synchronisation or diagnostic scripts'
          ],
          suggestedInvestigation: [
            'Identify the device owner and assigned role (e.g. workstation vs server).',
            'Determine whether the activity coincides with scheduled backups or maintenance.',
            'Review the destination addresses and protocols involved in the transfer.',
            'Check endpoint process logs (EDR/Sysmon) to identify the initiating executable.'
          ]
        });

        scoreItems.push({
          points: 20,
          label: `High packet volume (${src}: ${data.count} pkts)`
        });
      }
    }

    // RULE 2: Possible Host Scanning (High Unique Destinations)
    for (const [src, data] of sourceStats.entries()) {
      const uniqueCount = data.dests.size;
      if (uniqueCount > currentThresholds.uniqueDest) {
        alerts.push({
          ruleId: 'RULE-2',
          name: 'Possible Host Scanning',
          severity: 'Medium',
          source: src,
          destination: `${uniqueCount} unique addresses`,
          observed: `Communicated with ${uniqueCount} distinct destinations`,
          threshold: `>${currentThresholds.uniqueDest} unique destinations`,
          whyMatters: 'A single host communicating with an unusually large number of destination systems over a capture may indicate active network discovery, ping sweeps, or horizontal scanning behaviour.',
          benignExplanations: [
            'Authorised network management or IT asset inventory scanners',
            'Vulnerability scanners or endpoint compliance audit tools',
            'P2P applications, BitTorrent clients, or distributed services',
            'Broadcast/multicast service discovery in busy enterprise subnets'
          ],
          suggestedInvestigation: [
            'Verify if the source host is an authorised network discovery scanner.',
            'Check whether the destination IPs are sequential (indicating automated sweep) or random.',
            'Review response rates (e.g. ICMP Unreachable or TCP RST packets).',
            'Interview the workstation user to confirm if discovery tools were launched.'
          ]
        });

        scoreItems.push({
          points: 20,
          label: `High unique destination fan-out (${src}: ${uniqueCount} targets)`
        });
      }
    }

    // RULE 3: Possible Port Scanning (Multiple Ports on Same Target)
    for (const [src, data] of sourceStats.entries()) {
      for (const [targetDst, portSet] of data.dportsByDest.entries()) {
        if (portSet.size > currentThresholds.uniquePorts) {
          alerts.push({
            ruleId: 'RULE-3',
            name: 'Possible Port Scanning',
            severity: 'Medium',
            source: src,
            destination: targetDst,
            observed: `Probed ${portSet.size} unique ports on ${targetDst}`,
            threshold: `>${currentThresholds.uniquePorts} unique ports`,
            whyMatters: 'One host sequentially contacting multiple destination ports on a single system is characteristic of port discovery (reconnaissance) to map available services.',
            benignExplanations: [
              'Scheduled vulnerability assessment or security configuration audit',
              'Complex multi-port enterprise software or database suite discovery',
              'Network troubleshooting tools (e.g., test-netconnection / nmap by IT)',
              'Application attempting multiple fallback ports after connection timeout'
            ],
            suggestedInvestigation: [
              'Inspect the targeted port numbers (common ports like 21, 22, 80, 445, 3389 vs high ephemeral).',
              'Check whether TCP SYN packets were received with corresponding open responses.',
              'Correlate with host firewall logs on the destination server.',
              'Confirm if an authorised vulnerability assessment window was open.'
            ]
          });

          scoreItems.push({
            points: 15,
            label: `Multi-port probe pattern (${src} → ${targetDst}: ${portSet.size} ports)`
          });
        }
      }
    }

    // RULE 4: High ICMP Activity
    for (const [src, data] of sourceStats.entries()) {
      if (data.icmp > currentThresholds.icmp) {
        alerts.push({
          ruleId: 'RULE-4',
          name: 'High ICMP Activity',
          severity: 'Low',
          source: src,
          destination: 'Various',
          observed: `${data.icmp} ICMP packets generated`,
          threshold: `>${currentThresholds.icmp} ICMP packets`,
          whyMatters: 'Unusually high ICMP traffic from one source can indicate active host discovery (ping sweep), automated network health monitoring, path MTU discovery loops, or denial-of-service attempts.',
          benignExplanations: [
            'Network administrator running continuous diagnostic pings (`ping -t`)',
            'Network monitoring systems (e.g., Zabbix, PRTG, Nagios, SolarWinds)',
            'Path MTU discovery or routing recalculation during topology changes',
            'Automated latency measurement scripts'
          ],
          suggestedInvestigation: [
            'Examine the ICMP types (Echo Request type 8, Echo Reply type 0, or Destination Unreachable type 3).',
            'Determine if requests are targeted at a single host or sweeping a subnet.',
            'Confirm if an automated monitoring probe is deployed on the source host.'
          ]
        });

        scoreItems.push({
          points: 15,
          label: `Elevated ICMP activity (${src}: ${data.icmp} packets)`
        });
      }
    }

    // RULE 5: High DNS Query Activity
    for (const [src, data] of sourceStats.entries()) {
      if (data.dns > currentThresholds.dns) {
        alerts.push({
          ruleId: 'RULE-5',
          name: 'High DNS Query Activity',
          severity: 'Low',
          source: src,
          destination: 'DNS Resolvers',
          observed: `${data.dns} DNS query packets generated`,
          threshold: `>${currentThresholds.dns} DNS packets`,
          whyMatters: 'A high frequency of DNS requests may be normal browsing or can indicate aggressive automated lookups, DNS tunneling, or domain-generation algorithm (DGA) beaconing.',
          benignExplanations: [
            'Intensive web browsing with dozens of third-party domains and trackers',
            'Mail server or web proxy performing reverse DNS lookups',
            'Software updates or cloud synchronisation clients resolving endpoints',
            'Misconfigured DNS client retrying against an unresponsive local resolver'
          ],
          suggestedInvestigation: [
            'Inspect query domain names in the Info column for high-entropy strings or unusual TLDs.',
            'Review the NXDOMAIN (domain not found) response rate from the resolver.',
            'Check query periodicity (e.g., regular interval beaconing vs bursty user browsing).'
          ]
        });

        scoreItems.push({
          points: 10,
          label: `Elevated DNS query volume (${src}: ${data.dns} queries)`
        });
      }
    }

    // RULE 6: Repeated Source-to-Destination Communication
    for (const [, pairData] of pairCounts.entries()) {
      if (pairData.count > currentThresholds.repeatedPair) {
        const topProto = getTopProtocol(pairData.protocols);
        alerts.push({
          ruleId: 'RULE-6',
          name: 'Repeated Source-to-Destination Traffic',
          severity: 'Low',
          source: pairData.src,
          destination: pairData.dst,
          observed: `${pairData.count} packets exchanged (Top Protocol: ${topProto})`,
          threshold: `>${currentThresholds.repeatedPair} packets between pair`,
          whyMatters: 'Persistent communication between a single host pair indicates sustained data transfer, continuous session streaming, or potential automated command-and-control polling.',
          benignExplanations: [
            'Active web download, video streaming, or file server replication',
            'Remote desktop (RDP) or secure shell (SSH) administration session',
            'Continuous API polling or database client connections',
            'Local network file transfer via SMB or NFS'
          ],
          suggestedInvestigation: [
            'Verify the nature of the application protocol in use (e.g. TLS, SMB, HTTP).',
            'Determine whether the destination is an internal server or external internet service.',
            'Examine packet size distribution: Are these data transfers or small periodic keep-alives?'
          ]
        });

        scoreItems.push({
          points: 10,
          label: `Heavy pair communication (${pairData.src} → ${pairData.dst}: ${pairData.count} pkts)`
        });
      }
    }

    // RULE 7: TCP SYN Heavy Activity
    for (const [src, data] of sourceStats.entries()) {
      if (data.syn > currentThresholds.tcpSyn) {
        alerts.push({
          ruleId: 'RULE-7',
          name: 'TCP SYN Heavy Activity',
          severity: 'Low',
          source: src,
          destination: 'Various',
          observed: `${data.syn} TCP [SYN] connection packets`,
          threshold: `>${currentThresholds.tcpSyn} SYN packets`,
          whyMatters: 'Repeated SYN packets indicate rapid connection initiation. In security investigations, this pattern may represent port scanning, connection retry loops against unavailable services, or SYN flood attempts.',
          benignExplanations: [
            'Modern web browsers opening parallel connections to CDNs and assets',
            'Application retrying connection after server dropped or timed out',
            'Performance benchmark or load testing in a test lab environment',
            'Network discovery tool checking for online services'
          ],
          suggestedInvestigation: [
            'Look at the destination ports to see if connection requests are spread out or concentrated.',
            'Check whether matching [SYN, ACK] replies were returned to establish full handshakes.',
            'Confirm if the remote service was offline, causing automatic client retries.'
          ]
        });

        scoreItems.push({
          points: 10,
          label: `Elevated TCP SYN rate (${src}: ${data.syn} SYN packets)`
        });
      }
    }

    allAlerts = alerts;

    // 3. Render Dashboard Metrics
    renderKPICards(currentPackets.length, sourceStats, destCounts, protocolCounts, totalLength, lengthCount);
    renderInvestigationScore(scoreItems);
    renderRankedTables(sourceStats, destCounts, currentPackets.length);
    renderProtocolBars(protocolCounts, currentPackets.length);
    populateFilterDropdowns(sourceStats, destCounts);
    renderAlerts();
    renderRawPacketsTable();
  }

  // -------------------------------------------------------------
  // Rendering Helpers
  // -------------------------------------------------------------
  function renderKPICards(totalPackets, sourceStats, destCounts, protocolCounts, totalLength, lengthCount) {
    kpiTotalPackets.textContent = totalPackets.toLocaleString();
    kpiSourceHosts.textContent = sourceStats.size.toLocaleString();
    kpiDestHosts.textContent = destCounts.size.toLocaleString();

    // Top Source
    let topSource = '—';
    let topSourceCount = 0;
    for (const [src, data] of sourceStats.entries()) {
      if (data.count > topSourceCount) {
        topSourceCount = data.count;
        topSource = src;
      }
    }
    kpiTopSource.textContent = topSource;
    kpiTopSourceCount.textContent = `${topSourceCount.toLocaleString()} packets`;

    // Top Destination
    let topDest = '—';
    let topDestCount = 0;
    for (const [dst, count] of destCounts.entries()) {
      if (count > topDestCount) {
        topDestCount = count;
        topDest = dst;
      }
    }
    kpiTopDest.textContent = topDest;
    kpiTopDestCount.textContent = `${topDestCount.toLocaleString()} packets`;

    // Top Protocol & Avg Length
    let topProto = '—';
    let topProtoCount = 0;
    for (const [p, c] of protocolCounts.entries()) {
      if (c > topProtoCount) {
        topProtoCount = c;
        topProto = p;
      }
    }
    kpiTopProtocol.textContent = topProto;
    const avgLen = lengthCount > 0 ? Math.round(totalLength / lengthCount) : 0;
    kpiAvgLength.textContent = `Avg len: ${avgLen} bytes`;
  }

  function renderInvestigationScore(scoreItems) {
    let totalScore = 0;
    for (const item of scoreItems) {
      totalScore += item.points;
    }

    scoreValue.textContent = totalScore;

    scoreBadge.className = 'score-badge';
    if (totalScore === 0) {
      scoreBadge.classList.add('badge-routine');
      scoreBadge.textContent = 'Routine Activity (0 pts)';
    } else if (totalScore <= 20) {
      scoreBadge.classList.add('badge-low-activity');
      scoreBadge.textContent = 'Low Priority Activity (1–20 pts)';
    } else if (totalScore <= 50) {
      scoreBadge.classList.add('badge-moderate');
      scoreBadge.textContent = 'Moderate Activity (21–50 pts)';
    } else {
      scoreBadge.classList.add('badge-elevated');
      scoreBadge.textContent = 'Elevated Activity (51+ pts)';
    }

    scoreBreakdownList.innerHTML = '';
    if (scoreItems.length === 0) {
      const li = document.createElement('li');
      li.className = 'empty-breakdown';
      li.textContent = 'No elevated activity triggers observed. Traffic appears routine according to configured thresholds.';
      scoreBreakdownList.appendChild(li);
    } else {
      scoreItems.forEach(item => {
        const li = document.createElement('li');
        li.className = 'score-item';
        
        const labelSpan = document.createElement('span');
        labelSpan.textContent = item.label;

        const ptsSpan = document.createElement('span');
        ptsSpan.className = 'score-item-pts';
        ptsSpan.textContent = `+${item.points} pts`;

        li.appendChild(labelSpan);
        li.appendChild(ptsSpan);
        scoreBreakdownList.appendChild(li);
      });
    }
  }

  function renderRankedTables(sourceStats, destCounts, totalPackets) {
    // Sort Sources
    const sortedSources = Array.from(sourceStats.entries())
      .map(([src, d]) => ({ host: src, count: d.count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    topSourcesBody.innerHTML = '';
    sortedSources.forEach((entry, idx) => {
      const pct = totalPackets > 0 ? ((entry.count / totalPackets) * 100).toFixed(1) : 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>#${idx + 1}</td>
        <td class="mono"><strong>${escapeHTML(entry.host)}</strong></td>
        <td class="text-right mono">${entry.count.toLocaleString()}</td>
        <td class="table-bar-cell">
          <div class="inline-bar-wrap" title="${pct}% of total packets">
            <div class="inline-bar-fill" style="width: ${pct}%;"></div>
          </div>
        </td>
      `;
      topSourcesBody.appendChild(tr);
    });

    // Sort Destinations
    const sortedDestinations = Array.from(destCounts.entries())
      .map(([dst, count]) => ({ host: dst, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 10);

    topDestinationsBody.innerHTML = '';
    sortedDestinations.forEach((entry, idx) => {
      const pct = totalPackets > 0 ? ((entry.count / totalPackets) * 100).toFixed(1) : 0;
      const tr = document.createElement('tr');
      tr.innerHTML = `
        <td>#${idx + 1}</td>
        <td class="mono"><strong>${escapeHTML(entry.host)}</strong></td>
        <td class="text-right mono">${entry.count.toLocaleString()}</td>
        <td class="table-bar-cell">
          <div class="inline-bar-wrap" title="${pct}% of total packets">
            <div class="inline-bar-fill" style="width: ${pct}%;"></div>
          </div>
        </td>
      `;
      topDestinationsBody.appendChild(tr);
    });
  }

  function renderProtocolBars(protocolCounts, totalPackets) {
    protocolBarsContainer.innerHTML = '';
    const sortedProtocols = Array.from(protocolCounts.entries())
      .sort((a, b) => b[1] - a[1]);

    if (sortedProtocols.length === 0) {
      protocolBarsContainer.innerHTML = '<p class="empty-breakdown">No protocols identified.</p>';
      return;
    }

    sortedProtocols.forEach(([proto, count]) => {
      const pct = totalPackets > 0 ? ((count / totalPackets) * 100).toFixed(1) : 0;
      const row = document.createElement('div');
      row.className = 'protocol-bar-row';
      row.innerHTML = `
        <span class="proto-label">${escapeHTML(proto)}</span>
        <div class="proto-bar-track" title="${escapeHTML(proto)}: ${count} packets (${pct}%)">
          <div class="proto-bar-fill" style="width: ${pct}%;"></div>
        </div>
        <span class="proto-stat">${count} (${pct}%)</span>
      `;
      protocolBarsContainer.appendChild(row);
    });
  }

  function populateFilterDropdowns(sourceStats, destCounts) {
    // Preserve current selections if still valid
    const currentSrc = filterSourceIp.value;
    const currentDst = filterDestIp.value;

    filterSourceIp.innerHTML = '<option value="ALL">All Sources</option>';
    Array.from(sourceStats.keys()).sort().forEach(src => {
      const opt = document.createElement('option');
      opt.value = src;
      opt.textContent = src;
      filterSourceIp.appendChild(opt);
    });
    if (Array.from(sourceStats.keys()).includes(currentSrc)) {
      filterSourceIp.value = currentSrc;
    }

    filterDestIp.innerHTML = '<option value="ALL">All Destinations</option>';
    Array.from(destCounts.keys()).sort().forEach(dst => {
      const opt = document.createElement('option');
      opt.value = dst;
      opt.textContent = dst;
      filterDestIp.appendChild(opt);
    });
    if (Array.from(destCounts.keys()).includes(currentDst)) {
      filterDestIp.value = currentDst;
    }
  }

  function renderAlerts() {
    const sevFilter = filterSeverity.value;
    const srcFilter = filterSourceIp.value;
    const dstFilter = filterDestIp.value;
    const searchTerm = filterSearchText.value.trim().toLowerCase();

    const filtered = allAlerts.filter(alert => {
      if (sevFilter !== 'ALL' && alert.severity !== sevFilter) return false;
      if (srcFilter !== 'ALL' && alert.source !== srcFilter) return false;
      if (dstFilter !== 'ALL' && alert.destination !== dstFilter) return false;
      if (searchTerm) {
        const text = `${alert.name} ${alert.source} ${alert.destination} ${alert.observed} ${alert.whyMatters}`.toLowerCase();
        if (!text.includes(searchTerm)) return false;
      }
      return true;
    });

    alertsCountBadge.textContent = `${filtered.length} Alert${filtered.length === 1 ? '' : 's'}`;
    alertsContainer.innerHTML = '';

    if (filtered.length === 0) {
      const emptyCard = document.createElement('div');
      emptyCard.className = 'alert-card';
      emptyCard.style.textAlign = 'center';
      emptyCard.style.padding = '2rem';
      emptyCard.innerHTML = `
        <h4 style="color: #34d399; margin-bottom: 0.25rem;">No Matching Alerts</h4>
        <p style="font-size: 0.88rem;">No suspicious patterns match the current filters or thresholds.</p>
      `;
      alertsContainer.appendChild(emptyCard);
      return;
    }

    filtered.forEach(alert => {
      const card = document.createElement('article');
      card.className = `alert-card severity-${alert.severity.toLowerCase()}`;

      let tagClass = 'tag-info';
      if (alert.severity === 'High') tagClass = 'tag-high';
      else if (alert.severity === 'Medium') tagClass = 'tag-medium';
      else if (alert.severity === 'Low') tagClass = 'tag-low';

      card.innerHTML = `
        <div class="alert-header">
          <div class="alert-title-wrap">
            <span class="severity-tag ${tagClass}">${escapeHTML(alert.severity)}</span>
            <h3 class="alert-title">${escapeHTML(alert.name)}</h3>
          </div>
          <span class="badge badge-subtle">Rule ID: ${escapeHTML(alert.ruleId)}</span>
        </div>

        <div class="alert-entities">
          <div class="entity-item">
            <span class="entity-label">Source Host:</span>
            <span class="entity-value">${escapeHTML(alert.source)}</span>
          </div>
          <div class="entity-item">
            <span class="entity-label">Target / Scope:</span>
            <span class="entity-value">${escapeHTML(alert.destination)}</span>
          </div>
          <div class="entity-item">
            <span class="entity-label">Observed:</span>
            <span class="entity-value">${escapeHTML(alert.observed)}</span>
          </div>
          <div class="entity-item">
            <span class="entity-label">Threshold:</span>
            <span class="entity-value">${escapeHTML(alert.threshold)}</span>
          </div>
        </div>

        <div class="alert-body-grid">
          <div class="alert-box">
            <div class="alert-box-title">Why This Could Matter</div>
            <p>${escapeHTML(alert.whyMatters)}</p>
          </div>

          <div class="alert-box">
            <div class="alert-box-title">Possible Benign Explanations</div>
            <ul>
              ${alert.benignExplanations.map(exp => `<li>${escapeHTML(exp)}</li>`).join('')}
            </ul>
          </div>

          <div class="alert-box investigation-box">
            <div class="alert-box-title">Suggested SOC Investigation Steps</div>
            <ol>
              ${alert.suggestedInvestigation.map(step => `<li>${escapeHTML(step)}</li>`).join('')}
            </ol>
          </div>
        </div>
      `;
      alertsContainer.appendChild(card);
    });
  }

  function renderRawPacketsTable() {
    rawPacketCountLabel.textContent = currentPackets.length.toLocaleString();
    const filterQuery = (packetSearchInput.value || '').trim().toLowerCase();

    packetsTableBody.innerHTML = '';
    let matches = 0;
    const maxRender = 150; // Cap at 150 rows in DOM to avoid DOM performance slowdown with large CSVs

    for (let i = 0; i < currentPackets.length; i++) {
      const pkt = currentPackets[i];
      if (filterQuery) {
        const line = `${pkt.no} ${pkt.time} ${pkt.source} ${pkt.destination} ${pkt.protocol} ${pkt.info}`.toLowerCase();
        if (!line.includes(filterQuery)) continue;
      }

      matches++;
      if (matches <= maxRender) {
        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>${escapeHTML(pkt.no)}</td>
          <td>${escapeHTML(pkt.time)}</td>
          <td><strong>${escapeHTML(pkt.source)}</strong></td>
          <td>${escapeHTML(pkt.destination)}</td>
          <td><span class="badge badge-subtle">${escapeHTML(pkt.protocol)}</span></td>
          <td>${pkt.length} B</td>
          <td style="word-break: break-all;">${escapeHTML(pkt.info)}</td>
        `;
        packetsTableBody.appendChild(tr);
      }
    }

    if (matches > maxRender) {
      packetFilterMatchCount.textContent = `Showing 1–${maxRender} of ${matches} matching packets`;
    } else {
      packetFilterMatchCount.textContent = `Showing ${matches} packet${matches === 1 ? '' : 's'}`;
    }
  }

  // -------------------------------------------------------------
  // Event Listeners & File Handlers
  // -------------------------------------------------------------
  
  // Click Drop Zone to Browse
  dropZone.addEventListener('click', () => fileInput.click());
  dropZone.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      fileInput.click();
    }
  });

  // Drag and Drop
  dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
  });

  dropZone.addEventListener('dragleave', () => {
    dropZone.classList.remove('dragover');
  });

  dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });

  // File Input Change
  fileInput.addEventListener('change', (e) => {
    if (e.target.files && e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  function handleFile(file) {
    if (!file) return;
    const name = file.name || 'uploaded.csv';
    const isCsv = name.toLowerCase().endsWith('.csv') || file.type.includes('csv') || file.type.includes('text');

    if (!isCsv) {
      showErrorState(name, 'Selected file does not appear to be a CSV. Please export your Wireshark capture as CSV.');
      return;
    }

    const reader = new FileReader();
    reader.onload = (evt) => {
      const content = evt.target.result;
      processCSVData(content, name, false);
    };
    reader.onerror = () => {
      showErrorState(name, 'Failed to read file from disk.');
    };
    reader.readAsText(file);
  }

  // Demo Buttons
  btnDemoNormal.addEventListener('click', () => {
    processCSVData(DEMO_SAMPLES.normal, 'normal-traffic.csv', true);
  });

  btnDemoHighVolume.addEventListener('click', () => {
    processCSVData(DEMO_SAMPLES.highVolume, 'high-volume-traffic.csv', true);
  });

  btnDemoMixedLab.addEventListener('click', () => {
    processCSVData(DEMO_SAMPLES.mixedLab, 'mixed-soc-lab.csv', true);
  });

  // Clear Data Button
  btnClearData.addEventListener('click', () => {
    currentPackets = [];
    currentFileName = '';
    isDemoData = false;
    allAlerts = [];

    fileStatusBar.style.display = 'none';
    emptyState.style.display = 'block';
    resultsContainer.style.display = 'none';
    btnClearData.style.display = 'none';
    fileInput.value = '';
  });

  // Thresholds Toggle
  settingsToggle.addEventListener('click', () => {
    const isExpanded = settingsToggle.getAttribute('aria-expanded') === 'true';
    settingsToggle.setAttribute('aria-expanded', !isExpanded);
    settingsBody.style.display = isExpanded ? 'none' : 'block';
  });

  settingsToggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      settingsToggle.click();
    }
  });

  // Apply Thresholds
  btnApplyThresholds.addEventListener('click', () => {
    currentThresholds.highVolume = parseInt(inputHighVolume.value, 10) || DEFAULT_THRESHOLDS.highVolume;
    currentThresholds.uniqueDest = parseInt(inputUniqueDest.value, 10) || DEFAULT_THRESHOLDS.uniqueDest;
    currentThresholds.uniquePorts = parseInt(inputUniquePorts.value, 10) || DEFAULT_THRESHOLDS.uniquePorts;
    currentThresholds.icmp = parseInt(inputIcmp.value, 10) || DEFAULT_THRESHOLDS.icmp;
    currentThresholds.dns = parseInt(inputDns.value, 10) || DEFAULT_THRESHOLDS.dns;
    currentThresholds.repeatedPair = parseInt(inputRepeatedPair.value, 10) || DEFAULT_THRESHOLDS.repeatedPair;
    currentThresholds.tcpSyn = parseInt(inputTcpSyn.value, 10) || DEFAULT_THRESHOLDS.tcpSyn;

    if (currentPackets.length > 0) {
      runTriageAnalysis();
    }
  });

  // Reset Defaults
  btnResetThresholds.addEventListener('click', () => {
    currentThresholds = { ...DEFAULT_THRESHOLDS };
    inputHighVolume.value = DEFAULT_THRESHOLDS.highVolume;
    inputUniqueDest.value = DEFAULT_THRESHOLDS.uniqueDest;
    inputUniquePorts.value = DEFAULT_THRESHOLDS.uniquePorts;
    inputIcmp.value = DEFAULT_THRESHOLDS.icmp;
    inputDns.value = DEFAULT_THRESHOLDS.dns;
    inputRepeatedPair.value = DEFAULT_THRESHOLDS.repeatedPair;
    inputTcpSyn.value = DEFAULT_THRESHOLDS.tcpSyn;

    if (currentPackets.length > 0) {
      runTriageAnalysis();
    }
  });

  // Alert Filters
  filterSeverity.addEventListener('change', renderAlerts);
  filterSourceIp.addEventListener('change', renderAlerts);
  filterDestIp.addEventListener('change', renderAlerts);
  filterSearchText.addEventListener('input', renderAlerts);

  btnResetFilters.addEventListener('click', () => {
    filterSeverity.value = 'ALL';
    filterSourceIp.value = 'ALL';
    filterDestIp.value = 'ALL';
    filterSearchText.value = '';
    renderAlerts();
  });

  // Raw Packets Table Toggle & Search
  rawPacketsToggle.addEventListener('click', () => {
    const isExpanded = rawPacketsToggle.getAttribute('aria-expanded') === 'true';
    rawPacketsToggle.setAttribute('aria-expanded', !isExpanded);
    rawPacketsBody.style.display = isExpanded ? 'none' : 'block';
  });

  rawPacketsToggle.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault();
      rawPacketsToggle.click();
    }
  });

  packetSearchInput.addEventListener('input', renderRawPacketsTable);

})();
