#!/usr/bin/env python2
#Author Phinfinity <rndanish@gmail.com>
"""
Simple hacked up https transparent proxy
works on desktops/laptops running linux
Add iptables rules (in order):
iptables -t nat -A OUTPUT -d 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1 -j ACCEPT
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to 127.0.0.1:1234
"""
import logging
import threading
import os
import signal
from socket import *
import struct
import binascii
import time as time
import sys
import pycurl
from datetime import datetime

logging.basicConfig()
logger = logging.getLogger("proxy")
logger.setLevel(logging.DEBUG)
SO_ORIGINAL_DST = 80
PROXY_HOST = "192.168.0.1"
PROXY_PORT = 8080
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 1234
SERVER_CONN_BUFFER = 20
index = -1

SERVER_NAME_LEN = 256
TLS_HEADER_LEN = 5
TLS_HANDSHAKE_CONTENT_TYPE = 0x16 # hex
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
printBuffer = False

def MIN(X, Y):
    #return ((X) < (Y) ? (X) : (Y)) C version
    return X if (X < Y) else Y

tls_alert = { 0x15, # TLS Alert */
0x03, 0x01, #/* TLS version  */
0x00, 0x02, #/* Payload length */
0x02, 0x28, #/* Fatal, handshake failure */
}


def getConnectionID():
    global index
    index += 1
    return index

def getStamp(index):
    return "Conn: " + str(index) + " [" + str(datetime.now().microsecond) + "] "

class TCPSocketPipe:
    def __init__(self, sourceSocket, destSocket, connID, isBlocking=True):
        self.connID = connID
        self.sourceSocket = sourceSocket
        self.destSocket = destSocket
        self.callback = None
        self.thread = None
        #self.sourceSocket.setblocking(isBlocking)
        
    def _connectPipe(self, logStr, *args, **kwargs):
        try:
            while True:
                try:
                    data = self.sourceSocket.recv(2048)
                    data2 = []
                    code = 0
                    if self.callback is not None:
                        retv = self.callback(data)
                        data2 = retv.data
                        code = retv.result
                        if retv.result == -1:
                            logger.info(getStamp(self.connID) + logStr + " : Callback returned False; Closing Pipe")
                            break;
                    
                    if code != -1:
                        # sent callback data first then send our data
                        if code == 0 or code == 1:
                            if len(data2) > 0:
                                logger.info(getStamp(self.connID) + logStr + " Sending returned data")
                                self.destSocket.send(data2)
                        
                        if code == 0 or code == 2:
                            if len(data) > 0:
                                logger.info(getStamp(self.connID) + logStr + " Sending data")
                                self.destSocket.send(data)
                    else:
                        logger.info(getStamp(self.connID) + logStr + " Not sending response: Code: %d" % code)
                        
                    if len(data) == 0 or code == -1:
                        print("Leaving0................................")
                        return
                except EOFError as e:
                    print(e)
                    continue
                except BaseException as e:
                    #if e.errno == 11:
                    #    print("Waiting............................................")
                    #    time.sleep(1)
                    #    continue
                    #else:
                    print(e)
                    print("Leaving1................................")
                    break;
                else:
                    if len(data) == 0:
                        print("Leaving2................................")
                        break;
                #logger.info(logStr + " : " + binascii.hexlify(data))
        except BaseException as e:
            logger.info(getStamp(self.connID) + logStr + " Socket Pipe Exception: " + str(e))
        finally:
            try:
                logger.info(getStamp(self.connID) + "Closing the source socket")
                self.sourceSocket.shutdown(SHUT_RDWR)
                self.sourceSocket.close()
            except error:
                pass
            try:
                logger.info(getStamp(self.connID) + "Closing the dest socket")
                self.destSocket.shutdown(SHUT_RDWR)
                self.destSocket.close()
            except error:
                pass
            
    def setCallback(self, callback):
        self.callback = callback
        
    def connectPipe(self, logStr):
        if self.thread is None:
            self.thread = threading.Thread(target=self._connectPipe, args=(logStr))
            self.thread.start()
        
    def join(self):
        self.thread.join()
    
    def preConnectSourceWrite(self, data):
        self.sourceSocket.send(data)
        
    def preConnectDestWrite(self, data):
        self.destSocket.send(data)

class CallbackStatus:
    def __init__(self, result, data=[]):
        # 0 = ok, use both "datas" (bitmask 00); 1 = ok, ignore return data (bitmask 01), 2 = ok, ignore callback data (bitmask 10); 3 ok, ignore all data (bitmask 11); -1 = failed
        self.result = result
        self.data = data
    
class HTTPProxyTunnel:
    def clientCallback(self, data):
        if printBuffer:
            logger.info(getStamp(self.connID) + "C->P: {\n %s \n}" % data)
        if self.cFirst:
            self.cFirst = False
            # Extract TLS SNI
            if self.connectSent is not None:
                logger.info(getStamp(self.connID) + "C->P Reading TLS SNI: Native Endianess: %s" % sys.byteorder)
                hostname = self.parse_tls_header(data)
                #self.hostname = hostname
                print(hostname)
                https_conn = "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                https_conn = https_conn.format(host=hostname, port=443)
                logger.info(getStamp(self.connID) + "HTTP Request: {\n" + https_conn + "\n}")
                data2 = str.encode(https_conn)
                self.connectSent = True
                return CallbackStatus(0, data2)
                
                
        return CallbackStatus(0)
        
    def proxyCallback(self, data):
        #TODO: Return a None if failed; and a filled array to send data; and an empty array to not send extra data; and an array with -1 to skip sending
        callbackCode = 0
        if self.pFirst and len(data) > 0:
            self.pFirst = False
            #if not data.startswith("HTTP/1.0 200") and not data.startswith("HTTP/1.1 200") and not data.startswith("HTTP/2 200") and not data.startswith("HTTP/1.1 3") and not data.startswith("HTTP/1.0 3"):
            if data.startswith(str.encode("HTTP/1.0 4")) or data.startswith(str.encode("HTTP/1.1 4")):
                logger.info(getStamp(self.connID) + "Wrapped connection failed")
                #logger.info(getStamp(self.connID) + "Got : P->C: {\n %s \n}" % data)
                callbackCode = -1
            else:
                logger.info(getStamp(self.connID) + "Wrapped connection looks fine")
                #logger.info("Got : %s", data.split('\n')[0])
                if self.connectSent == True:
                    callbackCode = 3
        
        if printBuffer:
            logger.info(getStamp(self.connID) + "P->C: {\n %s\n}" % data)
        return CallbackStatus(callbackCode)
        
    #Taken from the sniproxy project


#/* Parse a TLS packet for the Server Name Indication extension in the client
# * hello handshake, returning the first servername found (pointer to static
# * array)
# *
# * Returns:
# *  >=0  - length of the hostname and updates *hostname
# *         caller is responsible for freeing *hostname
# *  -1   - Incomplete request
# *  -2   - No Host header included in this request
# *  -3   - Invalid hostname pointer
# *  -4   - malloc failure
# *  < -4 - Invalid TLS client hello
# */
    def parse_tls_header(self, data2):
        data = bytearray(data2)
        logger.info(getStamp(self.connID) + " : " + data)
        index = TLS_HEADER_LEN
        tls_len = 0
        #/* Check that our TCP payload is at least large enough for a TLS header */
        if len(data) < TLS_HEADER_LEN:
            return -1
        
        tls_content_type = data[0] # index = 0
        logger.info(getStamp(self.connID) + " : " + str(data[0]) + " : " + str(type(data)))
        print(TLS_HANDSHAKE_CONTENT_TYPE)
        if tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE:
            print("Request did not begin with TLS handshake.\n")
            return -5
        
        tls_version_major = data[1] # index = 1
        tls_version_minor = data[2] # index = 2
        
        if tls_version_major < 3:
            print("Received SSL %d.%d handshake which can not support SNI.\n" % tls_version_major, tls_version_minor)
            return -2
        
        #/* TLS record length */
        tls_len = (data[3] << 8) + data[4] + TLS_HEADER_LEN # index = 3 and 4
        data_len = len(data)
        data_len = MIN(data_len, tls_len)

        #/* Check we received entire TLS record length */
        if data_len < tls_len:
            print("000000000000 : %d and %d" % (data_len, tls_len))
            return -1

        # * Handshake
        if index + 1 > data_len:
            print("111111111111")
            return -5

        if data[index] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            print("Not a client hello\n")
            return -5

        #/* Skip past fixed length records:
        # 1    Handshake Type
        # 3    Length
        # 2    Version (again)
        # 32    Random
        # to    Session ID Length
        # */
        index += 38

        #/* Session ID */
        if index + 1 > data_len:
            print("222222222222")
            return -5
        
        tls_len = data[index];
        index += 1 + tls_len

        #/* Cipher Suites */
        if index + 2 > data_len:
            print("333333333333")
            return -5
        
        tls_len = (data[index] << 8) + data[index + 1]
        index += 2 + tls_len

        #/* Compression Methods */
        if index + 1 > data_len:
            print("444444444444")
            return -5
        
        tls_len = data[index]
        index += 1 + tls_len

        if index == data_len and tls_version_major == 3 and tls_version_minor == 0:
            print("Received SSL 3.0 handshake without extensions\n")
            return -2

        #/* Extensions */
        if index + 2 > data_len:
            print("555555555555")
            return -5
        
        tls_len = (data[index] << 8) + data[index + 1]
        index += 2

        if index + tls_len > data_len:
            print("666666666666")
            return -5
        
        return self.parse_extensions(data, index, data_len)

    def parse_extensions(self, data, index, data_len):
        tls_len = 0
        
        #/* Parse each 4 bytes for the extension header */
        while index + 4 <= data_len:
            #/* Extension Length */
            tls_len = (data[index + 2] << 8) + data[index + 3]

            #/* Check if it's a server name extension */
            if data[index] == 0x00 and data[index + 1] == 0x00:
                #/* There can be only one extension of each type, so we break
                # our state and move p to beinnging of the extension here */
                if index + 4 + tls_len > data_len:
                    print("777777777777")
                    return -5
                
                #index + 4 + tls_len
                return self.parse_server_name_extension(data, index + 4, data_len)
            else:
                print("ABCDABCDABCD")
            index += 4 + tls_len # /* Advance to the next extension header */
        #/* Check we ended where we expected to */
        if index != data_len:
            print("888888888888")
            return -5

        print("999999999999")
        return -2
#[0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99, 111, 109, 0]
#[0, 11, 101, 120, 97, 109, 112, 108, 101, 46, 99]
    def parse_server_name_extension(self, data, index, data_len): #+2 = str len
        sni_len = 0
        while index + 4 < data_len:
            #sni_len = (data[index + 1] << 8) + data[index + 2]
            sni_len = (data[index + 3] << 8) + data[index + 4]
            #print("145153251 -> %d : %d : %d : %d" % (index + 5 + sni_len, data_len, sni_len, index))
            if (index + 5 + sni_len > data_len):
                print("AAAAAAAAAAAA -> %d : %d : %d : %d" % (index + 5 + sni_len, data_len, sni_len, index))
                return -5

            if (data[index + 2] == 0x00): #/* name type */
                #/* host_name */
                #*hostname = (char*) malloc(sni_len + 1)
                #if (*hostname == NULL)
                #    printf("malloc() failure\n")
                #    return -4

                hostnm = []
                for i in range(0, sni_len):
                    #print("Char: %s" % hex(data[(index + 5) + i]))
                    hostnm.append(data[(index + 5) + i])
                    #strncpy(*hostname, data + index + 3, sni_len)
                
                return "".join(map(chr, hostnm)) # Convert to a string
                #(*hostname)[sni_len] = '\0' # In C this would properly terminate the "string" ie. char[]

                #return hostnm
            else:
                print("Unknown server name extension name type: %d\n" % data[index])
            index += 3 + sni_len
        
        #/* Check we ended where we expected to */
        if index != data_len:
            print("BBBBBBBBBBBB")
            return -5

        print("CCCCCCCCCCCC")
        return -2

    def __init__(self, clientProxyPipe, proxyClientPipe, connID):
        self.connID = connID
        self.hostname = None
        self.connectSent = None
        
        self.clientProxyPipe = clientProxyPipe
        self.clientProxyPipe.setCallback(self.clientCallback)
        
        self.proxyClientPipe = proxyClientPipe
        self.proxyClientPipe.setCallback(self.proxyCallback)
    
        self.pFirst = True
        self.cFirst = True
        
    def runTunnel(self, fallbackIP, port):
        hostname = fallbackIP
        self.port = port
        
        # We start this first so that we can recieve the 
        # TLS ClientHello Message to retrieve the SNI value 
        # to use in the CONNECT request to the proxy
        
        # TODO: Extract the TLS SNI from the request to fix ssl errors
        if port == 80:
            self.connectSent = None
            # Use the Host header
            logger.info(getStamp(self.connID) + "Tunneling HTTP connection on proxy")
            
        elif port == 443:
            self.connectSent = False
            #if fallbackIP == "93.184.216.34":
            hostname = "example.com"
            #elif fallbackIP == "172.217.3.238":
            #    hostname = "google.com"
            #elif fallbackIP == "52.9.194.80" or fallbackIP == "50.18.192.251" or fallbackIP == "50.18.192.250":
            #    hostname = "duckduckgo.com"
            #elif fallbackIP == "171.20.53.203":
            #    hostname = "lego.com"
            #elif fallbackIP == "192.30.253.112" or fallbackIP == "192.30.253.113":
            #    hostname = "github.com"
            #elif fallbackIP == "130.89.148.14" or fallbackIP == "128.31.0.62" or fallbackIP == "5.153.231.4" or fallbackIP == "149.20.4.15":
            #    hostname = "debian.org" 

            # Use the TLS SNI Extension
            logger.info(getStamp(self.connID) + "Wrapping HTTPS connection on proxy")
            
            #hostname = str(self.hostname)
            # Establish the tunnel with the proxy for our pipes
            ##https_conn = "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
            ##https_conn = https_conn.format(host=hostname, port=port)
            ##logger.info(getStamp(self.connID) + "HTTP Request: {\n" + https_conn + "\n}")
            ##self.clientProxyPipe.preConnectDestWrite(str.encode(https_conn))
            ##self.connectSent = True
            #socket.send(https_conn)
            
        else:
            # Ignore
            logger.info(getStamp(self.connID) + "Ignoring %s:%d connection on proxy" % fallbackIP, port)
            return
            
        # Start the pipes
        self.clientProxyPipe.connectPipe("C") #->P Send
        self.proxyClientPipe.connectPipe("P") #->C Recv
        
        # Wait on the pipes
        self.clientProxyPipe.join()
        logger.info(getStamp(self.connID) + "Closed the Client -> Proxy socket pipe")
        self.proxyClientPipe.join()
        logger.info(getStamp(self.connID) + "Closed the Proxy -> Client socket pipe")
        
def handle_connection(s, addr):
    try:
        proxy_s = socket(AF_INET, SOCK_STREAM)
        proxy_s.connect((PROXY_HOST, PROXY_PORT))
        dst = s.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
        temp_addr = inet_ntoa(srv_ip)
        srv_host = temp_addr
        
        connID = getConnectionID()
        logger.info(getStamp(connID) + "Intercepted connection to %s:%d %s", srv_host, srv_port, addr)

        HTTPProxyTunnel(
            TCPSocketPipe(s, proxy_s, connID, True), 
            TCPSocketPipe(proxy_s, s, connID),
            connID
        ).runTunnel(srv_host, srv_port)
        logger.info(getStamp(connID) + "%s:%d Terminated", srv_host, srv_port)
    finally:
        try:
            logger.info(getStamp(connID) + "Closing the Proxy Socket")
            proxy_s.close()
        except error:
            pass
        try:
            logger.info(getStamp(connID) + "Closing the Client Socket")
            s.close()
        except error:
            pass

pid = os.getpid()
s = socket(AF_INET, SOCK_STREAM)
s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
s.bind((SERVER_HOST, SERVER_PORT))
s.listen(SERVER_CONN_BUFFER)
logger.info(getStamp(-1) + "pid:%d , Listening on %d", pid, SERVER_PORT)
while True:
    try:
        conn, addr = s.accept()
        threading.Thread(target=handle_connection, args=(conn, addr,)).start()
    except KeyboardInterrupt:
        os.kill(pid, signal.SIGKILL)

