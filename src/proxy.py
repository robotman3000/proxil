#!/usr/bin/env python3
#Author Phinfinity <rndanish@gmail.com> and robotman3000 https://robotman3000.github.io
"""
Simple hacked up https transparent proxy
works on desktops/laptops running linux
Add iptables rules (in order):
iptables -t nat -A OUTPUT -d 192.168.0.0/16,10.0.0.0/8,172.16.0.0/12,127.0.0.1 -j ACCEPT
iptables -t nat -A OUTPUT -p tcp --dport 80 -j DNAT --to 127.0.0.1:1234
iptables -t nat -A OUTPUT -p tcp --dport 443 -j DNAT --to 127.0.0.1:1234
"""
import logging, threading, os, signal, struct, binascii, sys
import time as time
from socket import *
from datetime import datetime

logging.basicConfig()
logger = logging.getLogger("proxy")
logger.setLevel(logging.DEBUG)
SO_ORIGINAL_DST = 80
PROXY_HOST = "192.168.0.1"
PROXY_PORT = 8080
SERVER_HOST = "0.0.0.0"
SERVER_PORT = 1234
SERVER_CONN_BUFFER = 200
index = -1
activeCount = 0
activeLock = False

SERVER_NAME_LEN = 256
TLS_HEADER_LEN = 5
TLS_HANDSHAKE_CONTENT_TYPE = 0x16 # hex
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01
printBuffer = False

def MIN(X, Y):
    return X if (X < Y) else Y
    
def getConnectionID():
    global index
    index += 1
    return index

def getStamp(index):
    return "Connection " + str(index) + " [" + str(datetime.now().microsecond) + "] "

class TCPSocketPipe:
    def __init__(self, sourceSocket, destSocket, connID, readWillBlock=True, writeWillBlock=True):
        self.connID = connID
        self.sourceSocket = sourceSocket
        self.destSocket = destSocket
        self.callback = None
        self.thread = None
        self.sourceSocket.setblocking(readWillBlock)
        self.destSocket.setblocking(writeWillBlock)
        
    def _connectPipe(self, logStr, *args, **kwargs):
        try:
            byteCount = 0
            while True:
                #TODO: Add propper support for non-blocking reads and writes to the sockets
                socketBuffer = self.sourceSocket.recv(2048)
                callbackBuffer = []
                bufferMode = 0
                if self.callback is not None:
                    callbackResult = self.callback(socketBuffer)
                    callbackBuffer = callbackResult.data
                    bufferMode = callbackResult.result
                    if bufferMode == -1:
                        logger.info(getStamp(self.connID) + logStr + " : Callback reported a failure; Closing Pipe")
                        break
                
                if len(socketBuffer) == 0 and len(callbackBuffer) == 0:
                    logger.info(getStamp(self.connID) + logStr + " : Callback and Socket buffers were empty; Closing Pipe")
                    break
                
                # Send callback data first then send our data
                # so that any data we inject takes presidence
                if bufferMode == 0 or bufferMode == 1:
                    if len(callbackBuffer) > 0:
                        logger.info(getStamp(self.connID) + logStr + " Sending callback data")
                        self.destSocket.send(callbackBuffer)
                        byteCount += len(callbackBuffer)
                
                if bufferMode == 0 or bufferMode == 2:
                    if len(socketBuffer) > 0:
                        #logger.info(getStamp(self.connID) + logStr + " Sending socket data")
                        self.destSocket.send(socketBuffer)
                        byteCount += len(socketBuffer)
                        
                if bufferMode == 3:
                    logger.info(getStamp(self.connID) + logStr + " Not sending response: Code: %d \n {\n %s \n} \n {\n %s \n}" % (bufferMode, callbackBuffer, socketBuffer))
                    
        except BaseException as e:
            logger.info(getStamp(self.connID) + logStr + " Socket Pipe Exception: " + str(e))
        finally:
            try:
                logger.info(getStamp(self.connID) + "Closing the source socket")
                self.sourceSocket.shutdown(SHUT_RDWR)
                self.sourceSocket.close()
            except BaseException as e:
                logger.info(getStamp(self.connID) + logStr + " Exception while closing source socket: " + str(e))
            try:
                logger.info(getStamp(self.connID) + "Closing the dest socket")
                self.destSocket.shutdown(SHUT_RDWR)
                self.destSocket.close()
            except BaseException as e:
                logger.info(getStamp(self.connID) + logStr + " Exception while closing destination socket: " + str(e))
            logger.info(getStamp(self.connID) + logStr + " Transfered %d Bytes" % byteCount)
            
    def setCallback(self, callback):
        self.callback = callback
        
    def connectPipe(self, logStr):
        if self.thread is None:
            self.thread = threading.Thread(target=self._connectPipe, args=(logStr))
            self.thread.start()
        
    def join(self):
        self.thread.join()

class CallbackStatus:
    def __init__(self, result, data=[]):
        # 0 = ok, use both "datas" (bitmask 00)
        # 1 = ok, ignore return data (bitmask 01)
        # 2 = ok, ignore callback data (bitmask 10)
        # 3 ok, ignore all data (bitmask 11)
        # -1 = failed
        self.result = result
        self.data = data
    
class HTTPProxyTunnel:
    def clientCallback(self, data):
        if printBuffer:
            logger.info(getStamp(self.connID) + "C->P: {\n %s \n}" % data)
            
        if self.cFirst and len(data) > 0:
            self.cFirst = False
            # Extract TLS SNI
            if self.connectSent is not None: # We are using TLS
                hostname = self.parse_tls_header(data)
                if isinstance(hostname, int):
                    # We got an error code
                    errStr = "Invalid TLS Client Hello"
                    if hostname == -1:
                        errStr = "Incomplete request"
                    elif hostname == -2:
                        errStr = "No Host header included in this request"
                        
                    logger.info(getStamp(self.connID) + "(%d) Failed to read SNI name: %s" % (hostname, errStr))
                        
                    return CallbackStatus(-1)
                else:                
                    https_conn = "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    https_conn = https_conn.format(host=hostname, port=443) # If connectSent is not None then the connection must be on 443
                    logger.info(getStamp(self.connID) + "HTTP Request: {\n" + https_conn + "\n}")
                    connectStr = str.encode(https_conn)
                    self.connectSent = True
                    return CallbackStatus(0, connectStr)
                
        return CallbackStatus(2)
        
    def proxyCallback(self, data):
        if printBuffer:
            logger.info(getStamp(self.connID) + "P->C: {\n %s \n}" % data)
            
        callbackCode = 0
        if self.pFirst and len(data) > 0:
            self.pFirst = False
            if self.connectSent is not None and data.startswith(str.encode("HTTP/1.0 4")) or data.startswith(str.encode("HTTP/1.1 4")): #TODO: These 4* 's might need to become 200's
                logger.info(getStamp(self.connID) + "Failed to wrap connection!")
                if not printBuffer:
                    logger.info(getStamp(self.connID) + "Upstream Proxy Responded With: P->C: {\n %s \n}" % data)
                callbackCode = -1
            else:
                logger.info(getStamp(self.connID) + "Successfully wrapped connection")
                if self.connectSent == True:
                    callbackCode = 3
    
        return CallbackStatus(callbackCode)
        
    #Taken from the sniproxy project and translated to python
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
        index = TLS_HEADER_LEN
        tls_len = 0
        #/* Check that our TCP payload is at least large enough for a TLS header */
        if len(data) < TLS_HEADER_LEN:
            return -1
        
        tls_content_type = data[0]
        if tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE:
            print("Request did not begin with TLS handshake.\n")
            return -5
        
        tls_version_major = data[1]
        tls_version_minor = data[2]
        
        if tls_version_major < 3:
            print("Received SSL %d.%d handshake which can not support SNI.\n" % tls_version_major, tls_version_minor)
            return -2
        
        #/* TLS record length */
        tls_len = (data[3] << 8) + data[4] + TLS_HEADER_LEN
        data_len = MIN(len(data), tls_len)

        #/* Check we received entire TLS record length */
        if data_len < tls_len: return -1

        # * Handshake
        if index + 1 > data_len: return -5

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
        if index + 1 > data_len: return -5
        
        tls_len = data[index];
        index += 1 + tls_len

        #/* Cipher Suites */
        if index + 2 > data_len: return -5
        
        tls_len = (data[index] << 8) + data[index + 1]
        index += 2 + tls_len

        #/* Compression Methods */
        if index + 1 > data_len: return -5
        
        tls_len = data[index]
        index += 1 + tls_len

        if index == data_len and tls_version_major == 3 and tls_version_minor == 0:
            print("Received SSL 3.0 handshake without extensions\n")
            return -2

        #/* Extensions */
        if index + 2 > data_len: return -5
        
        tls_len = (data[index] << 8) + data[index + 1]
        index += 2

        if index + tls_len > data_len: return -5
        
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
                if index + 4 + tls_len > data_len: return -5
            
                return self.parse_server_name_extension(data, index + 4, data_len)

            index += 4 + tls_len # /* Advance to the next extension header */
        #/* Check we ended where we expected to */
        if index != data_len: return -5
        return -2

    def parse_server_name_extension(self, data, index, data_len):
        sni_len = 0
        while index + 4 < data_len:
            sni_len = (data[index + 3] << 8) + data[index + 4]
            if (index + 5 + sni_len > data_len): return -5

            if (data[index + 2] == 0x00): #/* name type */ 0x00 Is the SNI Extension id
                hostnm = []
                for i in range(0, sni_len):
                    hostnm.append(data[(index + 5) + i])
                
                return "".join(map(chr, hostnm)) # Convert to a string
            else:
                print("Unknown server name extension name type: %d\n" % data[index])
            index += 3 + sni_len
        
        #/* Check we ended where we expected to */
        if index != data_len: return -5

        return -2

    def __init__(self, clientSocket, proxySocket, connID):
        self.connID = connID
        self.hostname = None
        self.connectSent = None
        self.pFirst = True
        self.cFirst = True
    
        self.clientProxyPipe = TCPSocketPipe(clientSocket, proxySocket, connID) 
        self.clientProxyPipe.setCallback(self.clientCallback)
        
        self.proxyClientPipe = TCPSocketPipe(proxySocket, clientSocket, connID)
        self.proxyClientPipe.setCallback(self.proxyCallback)
    
    def runTunnel(self, fallbackIP, port):
        hostname = fallbackIP
        self.port = port
        
        # We start this first so that we can recieve the 
        # TLS ClientHello Message to retrieve the SNI value 
        # to use in the CONNECT request to the proxy
        
        if port == 80:
            self.connectSent = None
            logger.info(getStamp(self.connID) + "Tunneling HTTP connection to proxy")
        elif port == 443:
            self.connectSent = False
            logger.info(getStamp(self.connID) + "Wrapping HTTPS connection to proxy")
        else:
            logger.info(getStamp(self.connID) + "Ignoring %s:%d connection to proxy" % fallbackIP, port)
            return
            
        # Start the pipes
        self.clientProxyPipe.connectPipe("C->P") # Send
        self.proxyClientPipe.connectPipe("P->C") # Recv
        
        # Wait on the pipes
        self.clientProxyPipe.join()
        logger.info(getStamp(self.connID) + "Closed the Client -> Proxy socket pipe")
        self.proxyClientPipe.join()
        logger.info(getStamp(self.connID) + "Closed the Proxy -> Client socket pipe")

def main():
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
    
def handle_connection(s, addr):
    try:
        proxy_s = socket(AF_INET, SOCK_STREAM)
        proxy_s.connect((PROXY_HOST, PROXY_PORT))
        dst = s.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
        srv_host = inet_ntoa(srv_ip)
        
        connID = getConnectionID()
        logger.info(getStamp(connID) + "Intercepted connection to %s:%d from %s", srv_host, srv_port, addr)
        HTTPProxyTunnel(s, proxy_s, connID).runTunnel(srv_host, srv_port)
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
        logger.info(getStamp(connID) + "Ended connection %d", connID)

main()
