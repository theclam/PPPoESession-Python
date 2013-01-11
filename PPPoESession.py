#
# PPPoESession v0.2, January 2013
# by Foeh Mannay - see http://networkbodges.blogspot.com for more information
#

import md5
import time
import os
from scapy.all import *

# Some human-readable versions of hex type numbers
Service_Name = '\x01\x01'
Host_Unique = '\x01\x03'
AC_Cookie = '\x01\x04'
LCP = 49185
CHAP = 49699
IPCP = 32801
IPv4 = 33
PADI = 9
PADO = 7
PADR = 25
PADS = 101
PADT = 167
ConfReq = '\x01'
ConfAck = '\x02'
ConfNak = '\x03'
ConfRej = '\x04'
TermReq = '\x05'
TermAck = '\x06'
EchoReq = '\x09'
EchoRep = '\x0a'
MTU = '\x01\x04'
MAGIC = '\x05\x06'
Challenge = '\x01'
Response = '\x02'
Success = '\x03'
Reject = '\x04'
Address = '\x03\x06'
lastpkt = IP()

def word(value):
# Generates a two byte representation of the provided number
  return(chr((value/256)%256)+chr(value%256))

def TLV(type, value):
# Generates a TLV for a variable length string
  return(type+word(len(value))+value)

def confreq(payload):
# Generates a TLV for a variable length string
  return(ConfReq + '\x01' + word(len(payload)+4) + payload)

def parseconfreq(payload):
# Returns a tuple containing the IP address plus any additional junk from a ConfReq
  ip = ''
  other = ''
  if(len(payload) > 4 and payload[0:1] == ConfReq):
    i = 4;
    while(i < len(payload) and i < ord(payload[3:4])+(256 * ord(payload[2:3]))):
      type = payload[i:i+1]
      length = payload[i+1:i+2]
      value = payload[i+2:i+ord(length)]
      if(type + length == Address):
        ip = value
      else:
        other += type+length+value
      i = i + ord(length)
  return([ip, other])
    
class PPPoESession(Automaton):
# A class providing a PPPoE and PPP state machine
  randomcookie = False
  retries = 100
  iface="eth1"
  mac="00:60:6e:00:00:42"
  hu="\x7a\x0e\x00\x00"
  ac_cookie=""
  ac_mac="ff:ff:ff:ff:ff:ff"
  our_magic="\x01\x23\x45\x67"
  their_magic="\x00\x00\x00\x00"
  sess_id = 0
  servicename = ""
  username = ""
  password = ""
  chal_id = ""
  challenge = ""
  ipaddress = chr(0) + chr(0) + chr(0) + chr(0)
  gwipaddress = ''
  recvbuff = []
  maxrecv = 1000
  
  # Method to check whether packets are queued
  def recv_queuelen(self):
    return(len(self.recvbuff))

  # Method to get the first packet in the receive queue
  def recv_packet(self):
    if(len(self.recvbuff) > 0):
      return(self.recvbuff.pop())
    else:
      return(None)
  # Method to send an IP packet through the PPP session
  def send_packet(self,payload):
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPv4)/payload, iface=self.iface, verbose=False)

  def ip(self):
  # Method to find the current IP address
    return(str(ord(self.ipaddress[0:1]))+"."+str(ord(self.ipaddress[1:2]))+"."+str(ord(self.ipaddress[2:3]))+"."+str(ord(self.ipaddress[3:4])))

  def gw(self):
  # Method to find the current IP address
    return(str(ord(self.gwipaddress[0:1]))+"."+str(ord(self.gwipaddress[1:2]))+"."+str(ord(self.gwipaddress[2:3]))+"."+str(ord(self.gwipaddress[3:4])))

  def getcookie(self, payload):
  # Method to recover an AC-Cookie from PPPoE tags
    loc = 0
    while(loc < len(payload)):
      att_type = payload[loc:loc+2]
      att_len = (256 * ord(payload[loc+2:loc+3])) + ord(payload[loc+3:loc+4])
      if att_type == "\x01\x04":
        self.ac_cookie = payload[loc+4:loc+4+att_len]
        break
      loc = loc + att_len + 4

  def master_filter(self, pkt):
  # Filter out anything that's not PPPoE as our automaton won't be interested
    return (PPPoED in pkt or PPPoE in pkt)

# Define possible states
  @ATMT.state(initial=1)
  def START(self):
    pass
  @ATMT.state()
  def WAIT_PADO(self):
    pass
  @ATMT.state()
  def GOT_PADO(self):
    pass
  @ATMT.state()
  def WAIT_PADS(self):
    pass
  @ATMT.state()
  def START_LCP(self):
    pass
  @ATMT.state()
  def LCP_Request_Sent(self):
    pass
  @ATMT.state()
  def LCP_Ack_Received(self):
    pass
  @ATMT.state()
  def LCP_Ack_Sent(self):
    pass
  @ATMT.state()
  def LCP_OPEN(self):
    pass
  @ATMT.state()
  def AUTHENTICATING(self):
    pass
  @ATMT.state()
  def WAIT_AUTH_RESPONSE(self):
    pass
  @ATMT.state()
  def START_IPCP(self):
    pass
  @ATMT.state()
  def IPCP_Request_Sent(self):
    pass
  @ATMT.state()
  def IPCP_Ack_Received(self):
    pass
  @ATMT.state()
  def IPCP_BOTH_PEND(self):
    pass
  @ATMT.state()
  def IPCP_Ack_Sent(self):
    pass
  @ATMT.state()
  def IPCP_OPEN(self):
    pass
  @ATMT.state(error=1)
  def ERROR(self):
    pass
  @ATMT.state(final=1)
  def END(self):
    pass
# Define transitions
# Transitions from START
  @ATMT.condition(START)
  def send_padi(self):
    print "Starting PPPoED"
    sendp(Ether(src=self.mac, dst="ff:ff:ff:ff:ff:ff")/PPPoED()/Raw(load=TLV(Service_Name,self.servicename)+TLV(Host_Unique, self.hu)),iface=self.iface, verbose=False)
    raise self.WAIT_PADO()
#
# Transitions from WAIT_PADO
  @ATMT.timeout(WAIT_PADO, 3)
  def timeout_pado(self):
    print "Timed out waiting for PADO"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    raise self.START()
  @ATMT.receive_condition(WAIT_PADO)
  def receive_pado(self,pkt):
    if (PPPoED in pkt) and (pkt[PPPoED].code==PADO):
      self.ac_mac=pkt[Ether].src
      self.getcookie(pkt[Raw].load)
      raise self.GOT_PADO()
#
# Transitions from GOT_PADO
  @ATMT.condition(GOT_PADO)
  def send_padr(self):
    if(self.randomcookie):
      print "Random cookie being used"
      self.ac_cookie=os.urandom(16)
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoED(code=PADR)/Raw(load=TLV(Service_Name,self.servicename)+TLV(Host_Unique, self.hu)+TLV(AC_Cookie,self.ac_cookie)),iface=self.iface, verbose=False)
    raise self.WAIT_PADS()
#
# Transitions from WAIT_PADS
  @ATMT.timeout(WAIT_PADS, 1)
  def timeout_pads(self):
    print "Timed out waiting for PADS"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    raise self.GOT_PADO()
  @ATMT.receive_condition(WAIT_PADS)
  def receive_pads(self,pkt):
    if (PPPoED in pkt) and (pkt[PPPoED].code==PADS):
      self.sess_id = pkt[PPPoED].sessionid
      raise self.START_LCP()
  @ATMT.receive_condition(WAIT_PADS)
  def receive_padt(self,pkt):
    if (PPPoED in pkt) and (pkt[PPPoED].code==PADT):
      print "Received PADT"
      raise self.ERROR()
#
# Transitions from START_LCP
  @ATMT.condition(START_LCP)
  def lcp_send_confreq(self):
    print "Starting LCP"
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=confreq(MTU+word(1492)+MAGIC+self.our_magic)),iface=self.iface, verbose=False)
    raise self.LCP_Request_Sent()
#
# Transitions from LCP_Request_Sent
  @ATMT.timeout(LCP_Request_Sent, 3)
  def lcp_req_sent_timeout(self):
    print "Timed out waiting for LCP from peer"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=confreq(MTU+word(1492)+MAGIC+self.our_magic)),iface=self.iface, verbose=False)
    raise self.LCP_Request_Sent()
  @ATMT.receive_condition(LCP_Request_Sent, prio=1)
  def lcp_req_sent_rx_confreq(self,pkt):
  # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=ConfAck+pkt[Raw].load[1:]),iface=self.iface, verbose=False)
      raise self.LCP_Ack_Sent()
  @ATMT.receive_condition(LCP_Request_Sent, prio=2)
  def lcp_req_sent_rx_confack(self,pkt):
  # We received a ConfAck from the peer. Now we must wait for their ConfReq.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfAck and pkt[Ether].src==self.ac_mac):
      raise self.LCP_Ack_Received()
  @ATMT.receive_condition(LCP_Request_Sent, prio=3)
  def lcp_req_sent_rx_confnakrej(self,pkt):
  # We received a ConfNak or a ConfRej from the peer. In theory we could negotiate but we have no parameters to fall back on so just error.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfNak or pkt[Raw].load[0:1]==ConfRej) and pkt[Ether].src==self.ac_mac:
      raise self.ERROR()
#
## Transitions from LCP_Ack_Sent
  @ATMT.timeout(LCP_Ack_Sent, 3)
  def lcp_ack_sent_timeout(self):
    print "Timed out waiting for LCP from peer"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=confreq(MTU+word(1492)+MAGIC+self.our_magic)),iface=self.iface, verbose=False)
    raise self.LCP_Ack_Sent()
  @ATMT.receive_condition(LCP_Ack_Sent, prio=1)
  def lcp_ack_sent_rx_confack(self, pkt):
  # We received a ConfAck from the peer, so we are ready to play.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfAck and pkt[Ether].src==self.ac_mac):
      raise self.LCP_OPEN()
  @ATMT.receive_condition(LCP_Ack_Sent, prio=2)
  def lcp_ack_sent_rx_confreq(self,pkt):
  # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=ConfAck+pkt[Raw].load[1:]),iface=self.iface, verbose=False)
      raise self.LCP_Ack_Sent()
  @ATMT.receive_condition(LCP_Ack_Sent, prio=3)
  def lcp_ack_sent_rx_confnakrej(self,pkt):
  # We received a ConfNak or a ConfRej from the peer. In theory we could negotiate but we have no parameters to fall back on so just error.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfNak or pkt[Raw].load[0:1]==ConfRej) and pkt[Ether].src==self.ac_mac:
      raise self.ERROR()
#
# Transitions from LCP_Ack_Received
  @ATMT.timeout(LCP_Ack_Received, 3)
  def lcp_ack_recv_timeout(self):
    print "Timed out waiting for LCP from peer"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=confreq(MTU+word(1492)+MAGIC+self.our_magic)),iface=self.iface, verbose=False)
    raise self.LCP_Req_Sent()
  @ATMT.receive_condition(LCP_Ack_Received)
  def lcp_ack_recv_rx_confreq(self, pkt):
  # We received a ConfReq from the peer. Nak is not implemented, we just Ack anything we are sent.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=ConfAck+pkt[Raw].load[1:]),iface=self.iface, verbose=False)
      raise self.LCP_OPEN()
#
# Transitions from LCP_OPEN
  @ATMT.timeout(LCP_OPEN, 3)
  def auth_or_ipcp_timeout(self):
    print "Timed out waiting for authentication challenge or IPCP from peer"
    self.retries -= 1
    if(self.retries < 0):
      print "Too many retries, aborting."
      raise self.ERROR()
    raise self.LCP_OPEN()
  @ATMT.receive_condition(LCP_OPEN, prio=1)
  def get_challenge(self,pkt):
  # We received a CHAP challenge from the peer so we must authenticate ourself.
    if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1]==Challenge and pkt[Ether].src==self.ac_mac):
      print "Got CHAP Challenge, Authenticating"
      self.chal_id = pkt[Raw].load[1:2]
      chal_len = ord(pkt[Raw].load[4:5])
      self.challenge = pkt[Raw].load[5:5+chal_len]
      raise self.AUTHENTICATING()
  @ATMT.receive_condition(LCP_OPEN, prio=2)
  def lcp_open_get_IPCP(self,pkt):
  # Straight to IPCP if the peer doesn't challenge.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[Raw].load[0:1]==Challenge and pkt[Ether].src==self.ac_mac):
      print "Got IPCP - skipping authentication"
      raise self.START_IPCP()
#
## Transitions from AUTHENTICATING
  @ATMT.condition(AUTHENTICATING)
  def send_response(self):
    auth_hash = md5.new(self.chal_id + self.password + self.challenge).digest()
    resp_len = word(len(auth_hash + self.username)+5)
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=CHAP)/Raw(load=Response + self.chal_id + resp_len + '\x10' + auth_hash + self.username), iface=self.iface, verbose=False)
    raise self.WAIT_AUTH_RESPONSE()
#
## Transitions from WAIT_AUTH_RESPONSE
  @ATMT.timeout(WAIT_AUTH_RESPONSE, 3)
  def wait_auth_response_timeout(self):
  # We timed out waiting for an auth response. Re-send.
    auth_hash = md5.new(self.chal_id + self.password + self.challenge).digest()
    resp_len = word(len(auth_hash + self.username)+5)
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=CHAP)/Raw(load=Response + self.chal_id + resp_len + '\x10' + auth_hash + self.username), iface=self.iface, verbose=False)
    raise self.WAIT_AUTH_RESPONSE()
  @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=1)
  def wait_auth_response_rx_success(self,pkt):
  # We received a CHAP success so we can start IPCP.
    if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1]==Success and pkt[Ether].src==self.ac_mac):
      print "Authenticated OK"
      raise self.START_IPCP()
  @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=2)
  def wait_auth_response_rx_reject(self,pkt):
  # We received a CHAP reject and must terminate.
    if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1]==Reject and pkt[Ether].src==self.ac_mac):
      print "Authentication failed, reason: " + pkt[Raw].load[4:]
      raise self.ERROR()
  @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=3)
  def wait_auth_response_rx_echo(self,pkt):
  # Authentication can take a while so we should reply to echoes while we wait.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==EchoReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic), iface=self.iface, verbose=False)
      raise self.WAIT_AUTH_RESPONSE()
  @ATMT.receive_condition(WAIT_AUTH_RESPONSE, prio=4)
  def wait_auth_response_rx_challenge(self,pkt):
  # We received a CHAP challenge from the peer so we must authenticate ourself.
    if (PPP in pkt) and pkt[PPP].proto == CHAP and (pkt[Raw].load[0:1]==Challenge and pkt[Ether].src==self.ac_mac):
      self.chal_id = pkt[Raw].load[1:2]
      chal_len = ord(pkt[Raw].load[4:5])
      self.challenge = pkt[Raw].load[5:5+chal_len]
      raise self.AUTHENTICATING()
#
## Transitions from START_IPCP
  @ATMT.condition(START_IPCP)
  def start_ipcp_tx_confreq(self):
    print "Starting IPCP"
    sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
    raise self.IPCP_Request_Sent()
#
## Transitions from IPCP_Request_Sent
  @ATMT.timeout(IPCP_Request_Sent, 3)
  def ipcp_req_sent_timeout(self):
  # We timed out. Re-send Configure-Request.
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
      raise self.IPCP_Request_Sent()
  @ATMT.receive_condition(IPCP_Request_Sent, prio=1)
  def ipcp_req_sent_rx_confack(self,pkt):
  # We received a ConfAck and can proceed with the current parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfAck and pkt[Ether].src==self.ac_mac):
      raise self.IPCP_Ack_Received()
  @ATMT.receive_condition(IPCP_Request_Sent, prio=2)
  def ipcp_req_sent_rx_confnak(self,pkt):
  # We received a ConfNak and must adjust the current parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfNak and pkt[Ether].src==self.ac_mac):
      suggestion = pkt[PPP].do_build_payload()[6:10]
      print "Peer provided our IP as " + str(ord(suggestion[0:1])) + "." + str(ord(suggestion[1:2])) + "." + str(ord(suggestion[2:3])) + "." + str(ord(suggestion[3:4]))
      self.ipaddress = suggestion
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
      raise self.IPCP_Request_Sent()
  @ATMT.receive_condition(IPCP_Request_Sent, prio=3)
  def ipcp_req_sent_rx_confreq(self,pkt):
  # We received a ConfReq and must validate our peer's proposed parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      payload = pkt[PPP].do_build_payload()
      [gwip, otherstuff] = parseconfreq(payload)
      if(len(gwip) == 4 and otherstuff == ''):
        # If the other end just wants to negotiate its IP, we will take it.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfAck+payload[1:]), iface=self.iface, verbose=False)
        self.gwipaddress = gwip
        raise self.IPCP_Ack_Sent()
      else:
        # Otherwise we ConfRej the other parameters as they are not supported.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfRej+payload[1:2]+word(len(otherstuff)+4)+otherstuff), iface=self.iface, verbose=False)
        self.retries -= 1
        if(self.retries < 0):
          raise self.ERROR()
        else:
          raise self.IPCP_Request_Sent()
  @ATMT.receive_condition(IPCP_Request_Sent, prio=4)
  def ipcp_req_sent_rx_echo(self,pkt):
  # We received an LCP echo and need to reply.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==EchoReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic), iface=self.iface, verbose=False)
      raise self.IPCP_Request_Sent()
#
## Transitions from IPCP_Ack_Received
  @ATMT.timeout(IPCP_Ack_Received, 3)
  def ipcp_ack_recv_timeout(self):
  # We timed out. Re-send Configure-Request.
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
      raise self.IPCP_Request_Sent()
  @ATMT.receive_condition(IPCP_Ack_Received)
  def ipcp_ack_recv_got_confreq(self,pkt):
  # We received a ConfReq and must validate our peer's proposed parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      payload = pkt[PPP].do_build_payload()
      [gwip, otherstuff] = parseconfreq(payload)
      if(len(gwip) == 4 and otherstuff == ''):
        # If the other end just wants to negotiate its IP, we will take it.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfAck+payload[1:]), iface=self.iface, verbose=False)
        self.gwipaddress = gwip
        print "IPCP is OPEN"
        raise self.IPCP_OPEN()
      else:
        # Otherwise we ConfRej the other parameters as they are not supported.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfRej+payload[1:2]+word(len(otherstuff)+4)+otherstuff), iface=self.iface, verbose=False)
        self.retries -= 1
        if(self.retries < 0):
          raise self.ERROR()
        else:
          raise self.IPCP_Ack_Received()
#
## Transitions from IPCP_Ack_Sent
  @ATMT.timeout(IPCP_Ack_Sent, 3)
  def ipcp_ack_sent_timeout(self):
  # We timed out. Re-send Configure-Request.
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
      raise self.IPCP_Ack_Sent()
  @ATMT.receive_condition(IPCP_Ack_Sent, prio=1)
  def ipcp_ack_sent_rx_confack(self,pkt):
  # We received a ConfAck and can proceed with the current parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfAck and pkt[Ether].src==self.ac_mac):
      print "IPCP Open."
      raise self.IPCP_OPEN()
  @ATMT.receive_condition(IPCP_Ack_Sent, prio=2)
  def ipcp_ack_sent_rx_confnak(self,pkt):
  # We received a ConfNak and must adjust the current parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfNak and pkt[Ether].src==self.ac_mac):
      suggestion = pkt[PPP].do_build_payload()[6:10]
      print "Peer provided our IP as " + str(ord(suggestion[0:1])) + "." + str(ord(suggestion[1:2])) + "." + str(ord(suggestion[2:3])) + "." + str(ord(suggestion[3:4])) + "."
      self.ipaddress = suggestion
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=confreq(Address+self.ipaddress)), iface=self.iface, verbose=False)
      raise self.IPCP_Ack_Sent()
  @ATMT.receive_condition(IPCP_Ack_Sent, prio=3)
  def ipcp_ack_sent_rx_confreq(self,pkt):
  # We received a ConfReq and must re-validate our peer's proposed parameters.
    if (PPP in pkt) and pkt[PPP].proto == IPCP and (pkt[PPP].do_build_payload()[0:1]==ConfReq and pkt[Ether].src==self.ac_mac):
      payload = pkt[PPP].do_build_payload()
      [gwip, otherstuff] = parseconfreq(payload)
      if(len(gwip) == 4 and otherstuff == ''):
        # If the other end just wants to negotiate its IP, we will take it.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfAck+payload[1:]), iface=self.iface, verbose=False)
        self.gwipaddress = gwip
        raise self.IPCP_Ack_Sent()
      else:
        # Otherwise we ConfRej the other parameters as they are not supported.
        sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=IPCP)/Raw(load=ConfRej+payload[1:2]+word(len(otherstuff)+4)+otherstuff), iface=self.iface, verbose=False)
        self.retries -= 1
        if(self.retries < 0):
          raise self.ERROR()
        else:
          raise self.IPCP_Request_Sent()
#
## Transitions from IPCP_OPEN
  @ATMT.receive_condition(IPCP_OPEN, prio=1)
  def ipcp_open_got_ip(self,pkt):
  # An IP packet came in.
    if (PPP in pkt) and pkt[PPP].proto == IPv4 and pkt[Ether].src==self.ac_mac and len(self.recvbuff) < self.maxrecv:
      self.recvbuff.insert(0,pkt[IP])
      raise self.IPCP_OPEN()
  @ATMT.receive_condition(IPCP_OPEN, prio=2)
  def ipcp_open_got_echo(self,pkt):
  # Automatically respond to LCP echo requests.
    if (PPP in pkt) and pkt[PPP].proto == LCP and (pkt[Raw].load[0:1]==EchoReq and pkt[Ether].src==self.ac_mac):
      sendp(Ether(src=self.mac, dst=self.ac_mac)/PPPoE(sessionid=self.sess_id)/PPP(proto=LCP)/Raw(load=EchoRep + pkt[Raw].load[1:2] + word(8) + self.our_magic), iface=self.iface, verbose=False)
      raise self.IPCP_OPEN()
  @ATMT.receive_condition(IPCP_OPEN, prio=3)
  def ipcp_open_got_padt(self,pkt):
  # Shut down upon receipt of PADT.
    if (PPPoED in pkt) and (pkt[PPPoED].code==PADT):
      print "Received PADT, shutting down."
      raise self.ERROR()



