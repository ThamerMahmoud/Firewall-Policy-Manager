# Firewall-Policy-Manager
Facilitate the adding the policy and its objects over multiple vendors (SRX and Fortigate) 


# Usage
 
 Download all the files
 
 Firstly update the "FWList.csv" file with your firewall IPs, Names at the below template using any editor
 
   For Juniper SRX
 
      9,Cairo_SRX,10.200.15.13,Juniper_SRX,FALSE
 
   For Fortigate
 
      10,Egypt_FG1,10.201.63.158,Fortigate,FALSE


Run the Firewall-Policy-Manager.py file


After Running the file you will see the the GUI interface

    ##1. Add your username and password and remove the FO mark
     Note: you can add your username and password in the script and use the FO check box instead of add them every time
  
    ##2. Add the Sources/destinations IPs with the below consideration
      You Can add the IP and the IP name like FW1_1.2.3.4/32 or FWX_10.10.10.1/24
      You can add IP range like 10.10.10.1-10 or AH_10.10.10.2-65 or 10.10.10.1-10.10.10.15
      You can't use "-" at the name like FW-1_10.10.10.0/23
      You can add multiple IPs with the sepration of space or comma or new line
     
    ##3. Add the needed service with the below considration (Not mandatory)
     
      for you should add udp/sctp to the port like 25_UDP or 8888ScTp
      for port Range you should use "-"
      For TCP only the port number or with the TCP like 25 or TCP25

    ##4. Press "Run" button
