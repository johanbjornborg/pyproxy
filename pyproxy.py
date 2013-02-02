import socket, sys, re
from urlparse import urlparse

header_fields = ['Accept', 'Accept-Charset', 'Accept-Encoding', 'Accept-Language', 'Accept-Datetime',
'Authorization', 'Cache-Control', 'Cookie', 'Content-Length', 'Content-MD5', 'Content-Type',
'Date', 'Expect', 'From', 'Host', 'If-Match', 'If-Modified-Since', 'If-None-Match', 'If-Range', 'If-Unmodified-Since',
'Max-Forwards', 'Pragma', 'Proxy-Authorization', 'Range', 'Referer', 'TE', 'Upgrade', 'User-Agent', 'Via', 'Warning']      
def main():
   
    if len(sys.argv) <= 1:
        print 'Usage : "python pyproxy.py <server_ip>"\n[server_ip : It is the IP Address Of Proxy Server]'
        sys.exit(2)
    host = ''
    port = sys.argv[1]
        
    # Create a TCP socket connection, bind it to the specified port.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, int(port)))
    server_socket.listen(5)
    
    #Start serving requests...
    while True:
        print "Ready to serve..."
        client_socket, client_address = server_socket.accept()
        print 'Received connection request from: ', client_address
        client_thread(client_socket)
#        p = multiprocessing.Process(target=client_thread, args=(client_socket, client_address))
#        p.start()
#        p.join()
        
# THIS IS MY FUNCTION
def client_thread(cli_socket):
    _message = cli_socket.recv(1024)
#        print _message
    request = request_parser(_message)
    if request is not None:
        # Request is valid. Perform appropriate action.
        s = build_uri(request)
#            res = socket.getaddrinfo(request['host'], 80, 0, 0, socket.SOL_TCP)
        outbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#            outbound.bind(('',0)) # accept defapydev eclult OS behavior
#            for r in res:
#                if r[4] is not None:
#                    outbound.connect(r[4])
#                    break
        outbound.connect((request['host'], 80))
        outbound.sendall(s)
#        out_message = outbound.recv(4096)
        data = ""
        while True:
            try:
#                print "Receiving data..."
                data += outbound.recv(4096)
#                cli_socket.send(data)
            except socket.timeout:
                print "timed out"
                break
        cli_socket.sendall(data)
        outbound.close()
        cli_socket.close()
#            print res
        #Send request

        #Cache the results

    else:
        return None

def build_uri(request):
    """
    Takes a properly formatted HTTP request and returns the formatted URI request.
    Refer to RFC 1945 section 5.4.2 for details on how URI requests are formatted.
    @param request: Hash of a valid HTTP GET request.
    @return: A (hopefully) Valid URI
    """

    _headers = [(_h.split(':')[0], _h.split(':')[1]) for _h in request['headers'].splitlines() if _h.split(':')[0] in header_fields]
    _val = "".join("%s:%s\r\n" % h for h in _headers)
    _val += "Connection: close\r\n\r\n"
#    if '/' in url:
#        # implement later.
#        pass

    return _val
    
       
def request_parser(message):
    """
    Given a message received from a connected client, determine if it is a valid HTTP request.
    @
    @param message: Client HTTP request. 
    @return: Hash of valid URI fields.
    @return: None upon encountering an error.
    """
    regex = re.compile(r"""(?P<method>\w+) (?P<url>http.*) (?P<version>HTTP/\d\.\d)\r*\n*(?P<headers>.*)\r*\n""", re.DOTALL)
    match = regex.match(message)
    if match is not None:
        _method = match.group('method')
        _url = match.group('url')
        _version = match.group('version')
        _headers = match.group('headers')
        
        if 'GET' in _method:
            return {'method':_method, 'url':_url, 'version':_version, 'headers': _headers, 'host': urlparse(_url)[1]}
        else:
            print "Error 501: Not Implemented"
            return None
    else:
        print "Error 400: Bad Request"
        return None

            
def is_cached(filename):
    filename = filename.partition("/")[2] 
    print filename 
    fileExist = "false"
    file_to_use = "/" + filename
    print file_to_use

if __name__ == '__main__':
    main()
 


