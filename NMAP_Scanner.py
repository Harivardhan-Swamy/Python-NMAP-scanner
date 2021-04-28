#!usr/bin/python3
import nmap

scanner=nmap.PortScanner()

print('Welcome to my nmap port scanner replication'+'\r\n')
print('<---------------------------------------------------------->')
ip_addr=input("Input the IP address \n")
resp=input("""\n Enter the option you want
                 1)SYN ACK scan
                 2)UDP scan
                 3)Comprehensive scan \n""")
print("you have entered option number",resp)
if resp=='1':
    print("NMAP ver:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS')
    print(scanner.scaninfo())
    print("IP status : ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports are : ",scanner[ip_addr]['tcp'].keys())
elif resp=='2':
    print("NMAP ver:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sU')
    print(scanner.scaninfo())
    print("IP status : ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports are : ",scanner[ip_addr]['udp'].keys())
elif resp=='3':
    print("NMAP ver:",scanner.nmap_version())
    scanner.scan(ip_addr,'1-1024','-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("IP status : ",scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open ports are : ",scanner[ip_addr]['tcp'].keys())
else :
    print("INVALID NUMBER")
    print("<--------------------------------------------------->")
    exit()
        
print("<------------------------------------------------------------>")