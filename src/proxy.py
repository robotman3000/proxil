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
import logging, threading, os, signal, struct, binascii, sys, argparse
import time as time
from socket import *
from datetime import datetime

logging.basicConfig()
logger = logging.getLogger("proxy")
SO_ORIGINAL_DST = 80
SERVER_CONN_BUFFER = 512
index = -1
activeCount = 0
activeLock = False

SERVER_NAME_LEN = 256
TLS_HEADER_LEN = 5
TLS_HANDSHAKE_CONTENT_TYPE = 0x16 # hex
TLS_HANDSHAKE_TYPE_CLIENT_HELLO = 0x01

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
        self.waitCount = 0
        self.writeDone = False
        self.readDone = True
        
    def _connectPipe(self, logStr, *args, **kwargs):
        try:
            byteCount = 0
            while True:
                try:
                    #TODO: Finish propper support for non-blocking reads and writes to the sockets
                    socketBuffer = self.sourceSocket.recv(2048)
                    if self.waitCount > 0: self.waitCount -= 1
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
                            logger.debug(getStamp(self.connID) + logStr + " Sending callback data: %s" % callbackBuffer)
                            self.destSocket.send(callbackBuffer)
                            byteCount += len(callbackBuffer)
                            if self.waitCount > 0: self.waitCount -= 1
                    
                    if bufferMode == 0 or bufferMode == 2:
                        if len(socketBuffer) > 0:
                            logger.debug(getStamp(self.connID) + logStr + " Sending socket data")
                            self.destSocket.send(socketBuffer)
                            byteCount += len(socketBuffer)
                            if self.waitCount > 0: self.waitCount -= 1
                            
                    if bufferMode == 3:
                        leng = len("HTTP/1.0 200 Connection established\r\n\r\n")
                        if len(socketBuffer) > leng:
                            logger.debug(getStamp(self.connID) + logStr + " Sending socket data22")
                            self.destSocket.send(socketBuffer[leng:])
                            #print(socketBuffer[leng:])
                            byteCount += len(socketBuffer[leng:])
                            if self.waitCount > 0: self.waitCount -= 1
                        else:
                            logger.info(getStamp(self.connID) + logStr + " Not sending response: Code: %d \n {\n %s \n} \n {\n %s \n}" % (bufferMode, callbackBuffer, socketBuffer))
                except BlockingIOError as e:
                    logger.info(getStamp(self.connID) + logStr + " Waiting " + str(self.waitCount) + ": " + str(e))
                    time.sleep(0.1)
                    if self.waitCount < 50:
                        self.waitCount += 1
                    else:
                        pass
                        break
        except BaseException as e:
            logger.warning(getStamp(self.connID) + logStr + " Socket Pipe Exception: " + str(e))
        finally:
            try:
                logger.debug(getStamp(self.connID) + "Closing the source socket")
                self.sourceSocket.shutdown(SHUT_RDWR)
                self.sourceSocket.close()
            except BaseException as e:
                logger.warning(getStamp(self.connID) + logStr + " Exception while closing source socket: " + str(e))
            try:
                logger.debug(getStamp(self.connID) + "Closing the dest socket")
                self.destSocket.shutdown(SHUT_RDWR)
                self.destSocket.close()
            except BaseException as e:
                logger.warning(getStamp(self.connID) + logStr + " Exception while closing destination socket: " + str(e))
            logger.debug(getStamp(self.connID) + logStr + " Transfered %d Bytes" % byteCount)
            
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
        logger.debug(getStamp(self.connID) + "C->P: {\n %s \n}" % data)
            
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
                        
                    logger.error(getStamp(self.connID) + "(%d) Failed to read SNI name: %s" % (hostname, errStr))
                        
                    return CallbackStatus(-1)
                else:                
                    https_conn = "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}\r\n\r\n"
                    https_conn = https_conn.format(host=hostname, port=443) # If connectSent is not None then the connection must be on 443
                    logger.info(getStamp(self.connID) + "HTTP Request: {\n" + https_conn + "\n}")
                    connectStr = str.encode(https_conn)
                    self.connectSent = True
                    return CallbackStatus(0, connectStr)
    
        if self.connectSent is None: # We are using HTTP
            domain = ""
            res = "".join(map(chr, data)).split("\r\n")
            for i in res:
                #print("2 %s" % i)
                if i.startswith("Host: "):
                    domain = i[6:]
                    break
            res2 = res[0].split(" ")
            if res2[0].startswith("GET") or res2[0].startswith("POST"): #TODO: Add the rest
                res2[1] = "http://" + domain + res2[1]
            #print(res2[1])
            res[0] = " ".join(res2)
            #print(res)
            strin = ""
            ind = 0
            for i in res:
                strin += i
                if ind < (len(res) - 1):
                    strin += "\r\n"
                    ind += 1
            
            return CallbackStatus(1, str.encode(strin))
                
        return CallbackStatus(2)
        
    def proxyCallback(self, data):
        logger.debug(getStamp(self.connID) + "P->C: {\n %s \n}" % data)
            
        callbackCode = 0
        if self.pFirst and len(data) > 0:
            self.pFirst = False
            #print(self.connectSent)
            if self.connectSent is not None and (data.startswith(str.encode("HTTP/1.0 4")) or data.startswith(str.encode("HTTP/1.1 4"))): #TODO: These 4* 's might need to become 200's
                logger.error(getStamp(self.connID) + "Failed to wrap connection!")
                logger.error(getStamp(self.connID) + "Upstream Proxy Responded With: P->C: {\n %s \n}" % data)
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
            logger.error("Request did not begin with TLS handshake.")
            return -5
        
        tls_version_major = data[1]
        tls_version_minor = data[2]
        
        if tls_version_major < 3:
            logger.error("Received SSL %d.%d handshake which can not support SNI." % tls_version_major, tls_version_minor)
            return -2
        
        #/* TLS record length */
        tls_len = (data[3] << 8) + data[4] + TLS_HEADER_LEN
        data_len = MIN(len(data), tls_len)

        #/* Check we received entire TLS record length */
        if data_len < tls_len: return -1

        # * Handshake
        if index + 1 > data_len: return -5

        if data[index] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO:
            logger.error("Not a client hello")
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
            logger.error("Received SSL 3.0 handshake without extensions")
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
                logger.debug("Unknown server name extension name type: %d" % data[index])
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
    
        self.clientProxyPipe = TCPSocketPipe(clientSocket, proxySocket, connID, True, True) 
        self.clientProxyPipe.setCallback(self.clientCallback)
        
        self.proxyClientPipe = TCPSocketPipe(proxySocket, clientSocket, connID, True, True)
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
        logger.debug(getStamp(self.connID) + "Closed the Client -> Proxy socket pipe")
        self.proxyClientPipe.join()
        logger.debug(getStamp(self.connID) + "Closed the Proxy -> Client socket pipe")

def main():
    args = parseOptions()
    configureLogging(args)
    pid = os.getpid()
    s = socket(AF_INET, SOCK_STREAM)
    s.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
    s.bind((args.listen_ip, args.listen_port))
    s.listen(SERVER_CONN_BUFFER)
    logger.info(getStamp(-1) + "pid:%d , Listening on %s:%d", pid, args.listen_ip, args.listen_port)
    #print("Log Level: %d" % logger.getEffectiveLevel())
    
    threads = []
    newThreadCount = 0
    while True:
        try:
            conn, addr = s.accept()
            #handle_connection(conn, addr, args.dest_ip, args.dest_port) # This is single thread mode
            
            # Clean up old threads before we add new ones
            
            if newThreadCount > 10:
                logger.debug(getStamp(self.connID) + "Cleaning up dead threads")
                newThreadCount = 0
                for t in threads:
                    if not t.isAlive():
                        logger.debug(getStamp(self.connID) + "Removing Thread %s" % t.getName())
                        threads.remove(t)
            
            thrd = threading.Thread(target=handle_connection, args=(conn, addr, args.dest_ip, args.dest_port))
            thrd.start() # This is multi-thread mode
            threads.append(thrd)
            newThreadCount += 1
            
            
        except KeyboardInterrupt:
            os.kill(pid, signal.SIGKILL)
    
def parseOptions():
    parser = argparse.ArgumentParser(prog='PROG', usage='%(prog)s [options]')
    parser.add_argument('--verbose', '-v', action='count', dest="logLevel", default=0, help='The higher the value the more verbose. 0 is the same as --quiet')
    parser.add_argument('--quiet', '-q', action='store_true', dest="isQuiet", default=False, help='Disables all output')
    parser.add_argument('--show-errors', '-e', action='store_true', dest="showErrors", default=False, help='Print\'s errors even if quiet is enabled')
    parser.add_argument('--listen-ip', '-a', type=str, default="0.0.0.0", help='The IP Address to listen on')
    parser.add_argument('--listen-port', '-p', type=int, default=1234, help='The port to listen on')
    parser.add_argument('--dest-ip', '-d', type=str, default="proxy.example.com", help='The address of the HTTP proxy to tunnel connections with')
    parser.add_argument('--dest-port', '-P', type=int, default=8080, help='The port of the HTTP proxy to tunnel connections with')
    
    args = parser.parse_args()
    #print(args)
    return args
    
def configureLogging(args):
    if args.showErrors:
        # set logger to 40 to show crit and error
        logger.setLevel(logging.ERROR)
        
    if args.logLevel > 1:
        # set logger to 10
        logger.setLevel(logging.DEBUG)
    
    elif args.logLevel > 0:
        # set logger to 20
        logger.setLevel(logging.INFO)
        
    #elif args.logLevel > 0:
        # set logger to 30
    #    logger.setLevel(logging.WARNING)
    
    if args.isQuiet:
        # set logger to 60
        logger.setLevel(60)
    
def handle_connection(s, addr, proxyIP, proxyPort):
    try:
        proxy_s = socket(AF_INET, SOCK_STREAM)
        proxy_s.connect((proxyIP, proxyPort))
        dst = s.getsockopt(SOL_IP, SO_ORIGINAL_DST, 16)
        srv_port, srv_ip = struct.unpack("!2xH4s8x", dst)
        srv_host = inet_ntoa(srv_ip)
        
        connID = getConnectionID()
        logger.info(getStamp(connID) + "Intercepted connection to %s:%d from %s", srv_host, srv_port, addr)
        HTTPProxyTunnel(s, proxy_s, connID).runTunnel(srv_host, srv_port)
        logger.info(getStamp(connID) + "%s:%d Terminated", srv_host, srv_port)
    except BaseException as e:
        logger.warning(getStamp(connID) + " Exception while handling connection: " + str(e))
    finally:
        try:
            logger.debug(getStamp(connID) + "Closing the Proxy Socket")
            proxy_s.close()
        except BaseException as e:
            pass
        try:
            logger.debug(getStamp(connID) + "Closing the Client Socket")
            s.close()
        except BaseException as e:
            pass
        logger.debug(getStamp(connID) + "Ended connection %d", connID)

main()
