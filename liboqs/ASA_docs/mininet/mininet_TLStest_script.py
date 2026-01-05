#!/usr/bin/python

# Script for OQS-TLS benchmarking inside mininet VM
# Host h1 runs the OQS-TLS server and host h2 is the client
# Link parameters used: latency and packet loss (bandwith is the maximum allowed)
# run it with...
# Adapted from: https://github.com/mininet/mininet/wiki/Introduction-to-Mininet#setting-performance-parameters

import time
import os.path
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import CPULimitedHost
from mininet.link import TCLink
from mininet.util import dumpNodeConnections
from mininet.log import setLogLevel
from mininet.clean import cleanup
#from mininet.cli import CLI

#global data
latencies = ["1ms", "10ms", "30ms", "50ms","100ms"]
lossProbabilities = [2,5,10,1] #cannot use value 0
#certsAlgorithms = ["rsa", "ecdsa", "dilithium2", "dilithium3" ,"dilithium4", "falcon512", "falcon1024" ,"picnicl1full", "picnic3l3", "picnic3l5" , "rainbowIaclassic", "rainbowIIIcclassic" ,"rainbowVcclassic", "sphincsharaka128frobust", "sphincsharaka192frobust" , "sphincsharaka256frobust" , "sphincssha256128frobust" ,"sphincssha256192frobust" ,"sphincssha256256frobust" , "p256_dilithium2", "p256_dilithium3" , "p256_falcon512", "p256_picnicl1full" , "p256_rainbowIaclassic", "p256_sphincsharaka128frobust" , "p256_sphincssha256128frobust", "p384_dilithium4" , "p384_picnic3l3", "p384_rainbowIIIcclassic" , "p384_sphincssha256192frobust", "p384_sphincsharaka192frobust" , "p521_falcon1024", "p521_picnic3l5" , "p521_rainbowVcclassic", "p521_sphincssha256256frobust" , "p521_sphincsharaka256frobust", "rsa3072_dilithium2" , "rsa3072_falcon512", "rsa3072_picnicl1full", "rsa3072_rainbowIaclassic"]
certsAlgorithms = ["falcon512", "falcon1024"]
kexAlgorithms = ["kyber512", "kyber1024"]
NUMBER_HANDSHAKES = 1000

#create a net topology
class SingleSwitchTopo(Topo):
    def build( self, n=2 , linkLatency='0ms', linkLoss=0):
	switch = self.addSwitch( 's1' )
	#add hosts and links
	for h in range(n):
	    host = self.addHost( 'h%s' % (h + 1) )
	    #add link with the switch
	    self.addLink( host, switch,bw=100, delay=linkLatency)

#util function
def toMilliseconds(timeOutput):
    s = timeOutput[2:].split(".") #warning: minutes are discarded (treated as always zero)
    mili = int(s[1].replace("s",""))
    result = int(s[0])*1000 + mili
    return result

#Collect Results from s_client outputs
#output is as follows:
#Handshake bytes (read), Server PK size used, Handshake time (wall clock time), Handshake time (usr CPU time)
#After 'DONE' is the output of time cmd
def parseOutputData(outputClient):
    count = 0
    print(outputClient)
    for line in outputClient.split("\n"):
    	if "SSL handshake has read" in line:
	        handshakeBytes = line.split(" ")[4]
		count = count+1
	if "Server public key is" in line:
		serverPkSize = line.split(" ")[4]
		count = count+1
	if (count > 1):
		continue
    timeOutput = outputClient.split("DONE")[1].split("\n")
#    print("\t\tWall Time:"+timeOutput[2])
    wallTime = toMilliseconds(timeOutput[2].replace("real","").strip())
    usrTime = toMilliseconds(timeOutput[3].replace("user","").strip())
    return (handshakeBytes,serverPkSize,wallTime,usrTime)


#saves results
#(certName,kexName,handshakeSize,serverPKsize,avgWallClockTime,avgUsrCPUTime) or number of Connections/30s
#different files for each Mininet Parameter (packet loss %, latency)
def saveResult(filename, certName,kexName,handshakeSize,serverPKsize,avgWallClockTime,avgUsrCPUTime):
    if os.path.isfile(filename):
        fileObj = open(filename,"a")
        fileObj.write(certName +","+kexName+","+str(handshakeSize)+","+str(serverPKsize)+","+str(avgWallClockTime)+","+str(avgUsrCPUTime)+"\n")
    else:
        fileObj = open(filename,"w")
        #fileObj.write("ServerCert,KexName,numberEstablishedConnections\n")
        fileObj.write("ServerCert,KexName,HandshakeSize,serverPKsize(bits),AvgWallClockTime(ms),AvgUsrCPUTime(ms)\n")
        fileObj.write(certName +","+kexName+","+str(handshakeSize)+","+str(serverPKsize)+","+str(avgWallClockTime)+","+str(avgUsrCPUTime)+"\n")

    fileObj.close()

#Run a test specifying the latency parameter
#The test is different: objective is to find number of connections allowed
#results collected from s_time
def runLatencyTest(latencyParam):
    filename = "results_latency_"+latencyParam+"ms.txt"
    print("\t\t\tCreate network")
    topo = SingleSwitchTopo( n=2 ,linkLatency=latencyParam)  #Two hosts
    net = Mininet(topo=topo, link=TCLink)
    net.start()

    TLSserver = net.get('h1')
    TLSclient = net.get('h2')
    print("\t\t\tRUN (LATENCY) TEST ="+latencyParam)


    #for each server certificate!
    for certName in certsAlgorithms:
	print ("Server with " + certName)
	serverCmd = "/home/mininet/openssl/apps/openssl s_server -www -tls1_3 -cert /home/mininet/openssl/CERT/"+certName+"_srv.crt -key /home/mininet/openssl/CERT/"+certName+"_srv.key &"
	outputServer = TLSserver.cmd(serverCmd) #cmd goes to background
	#for each KEX available!
	for kexName in kexAlgorithms:
		print("\tKEX:"+kexName)
		avgWallClockTime = 0.0
		avgUsrCPUTime = 0.0
		handshakeSize = 0
		serverPKsize = 0
		for i in range(NUMBER_HANDSHAKES):
			#clientCmd = "/home/mininet/openssl/apps/openssl s_time -curves "+kexName + " -new -CAfile /home/mininet/openssl/CERT/" + certName +"_CA.crt -verify 4 -connect 10.0.0.1:4433"
			clientCmd = "time echo | /home/mininet/openssl/apps/openssl s_client -groups "+kexName + " -CAfile /home/mininet/openssl/CERT/" + certName +"_CA.crt -verify 4 -connect 10.0.0.1:4433"

			TLSclient.sendCmd(clientCmd)
			#wait client termination
			outputClient = TLSclient.waitOutput()
			(out1,out2,out3,out4) = parseOutputData(outputClient)
			avgWallClockTime = avgWallClockTime + out3
			avgUsrCPUTime = avgUsrCPUTime + out4
			handshakeSize = out1 #unused
			serverPKsize = out2

			#save outputs for later processing
		saveResult(filename,certName,kexName,handshakeSize,serverPKsize,avgWallClockTime/NUMBER_HANDSHAKES,avgUsrCPUTime/NUMBER_HANDSHAKES)

    #clean mininet for the next test
    print("------------------------------------------------------------\n")
    print("\t\t\tSTOPPING...")
    net.stop()
    cleanup()


#run baseline (no link variation)
def runBaseline():
    filename = "results_baseline.txt"
    print("\t\t\tCreate network")
    topo = SingleSwitchTopo( n=2)  #Two hosts
    net = Mininet(topo=topo)
    net.start()

    TLSserver = net.get('h1')
    TLSclient = net.get('h2')
    print("\t\t\tRUN (BASELINE) TEST")


    pass

#run test wrapper
def runTests():

    #run baseline (no link variation)
    #runBaseline()

    #run latency test
    for l in latencies:
        runLatencyTest(l)

    #run packet loss % test
    #for lp in lossProbabilities:
    #    runPacketLossTest(lp)



if __name__ == '__main__':
    setLogLevel( 'info' )
    runTests()

