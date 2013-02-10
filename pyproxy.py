import socket, sys, re, threading, logging
from functools import partial
from urlparse import urlparse

cache = {}

# List of all accepted URI headers. Connection is omitted because it is always replaced with 'close' anyway.
header_fields = ['Accept', 'Accept-Charset', 'Accept-Encoding', 'Accept-Language', 'Accept-Datetime',
'Authorization', 'Cache-Control', 'Cookie', 'Content-Length', 'Content-MD5', 'Content-Type',
'Date', 'Expect', 'From', 'Host', 'If-Match', 'If-Modified-Since', 'If-None-Match', 'If-Range', 'If-Unmodified-Since',
'Max-Forwards', 'Pragma', 'Proxy-Authorization', 'Range', 'Referer', 'TE', 'Upgrade', 'User-Agent', 'Via', 'Warning']    
  
def main():
   
    if len(sys.argv) <= 1:
        print 'Usage : "python pyproxy.py <server_port>"\n[server_port : It is the desired port for the Proxy Server]'
        sys.exit(2)
    host = ''
    port = sys.argv[1]
        
    # Create a TCP socket connection, bind it to the specified port.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, int(port)))
    server_socket.listen(5)
    
    print "Ready to serve..."
    
    #Start serving requests...
    while True:

        client_socket, client_address = server_socket.accept()
#        print 'Received connection request from: ', client_address

        t = threading.Thread(target=partial(client_thread, client_socket))
        t.start()
        

def client_thread(cli_socket):
    """
    Takes a client socket and retrieves a webpage from the internet on the client's behalf.
    Requests from client must come in the form of a valid URI.
    @param cli_socket: Incoming client socket (host,port)
    @see: build_uri(request) for more information on URI formatting.
    
    
    """
    _message = cli_socket.recv(1024)

    request = request_parser(_message)
    if 'error' not in request:
        cached_url = request['host'] + request['url']
        if cached_url in cache:
            print "Found %s in cache" % cached_url
            cli_socket.sendall(cache[cached_url])

        else:
            # Request is valid and not cached. Perform appropriate action.
            s = build_uri(request)
            outbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print request['host']
            outbound.connect((request['host'], 80))
            outbound.send(s)
            total_data = []
            while True:
                try:
                    data = outbound.recv(8192)
                    if not data:
                        break
                    total_data.append(data)
                except socket.timeout:
                    break
            
            #Send result to originating client
            data = ''.join(total_data)
            cli_socket.sendall(data)
        
            #Cache the results
            cache[cached_url] = data
            
            #Close server socket
            outbound.close()
        
        # Close the client socket
        cli_socket.close() 
    else:
        cli_socket.send(request['error'])
        return None


def build_uri(request):
    """
    Takes a properly formatted HTTP request and returns the formatted URI request.
    Refer to RFC 1945 section 5.4.2 for details on how URI requests are formatted.
    @param request: Hash of a valid HTTP GET request.
    @return: A (hopefully) valid URI
    """  
    _headers = [(_h.split(':')[0].strip(), _h.split(':')[1].strip()) for _h in request['headers'].splitlines() if _h.split(':')[0] in header_fields]
    _headers.insert(0, ('Connection', 'close'))
    
    # If a Host: header was not present in the client's request, build one manually.
    if 'Host' not in _headers:
        _headers.insert(0, ('Host', request['host']))
#        _val = "".join("%s: %s\r\n" % h for h in _headers)
#    else:
    _val = "".join("%s: %s\r\n" % h for h in _headers)
    _val += "\r\n"
    
    # Form the URI request in its entirety. 
    _s = "GET {0} {1} \r\n{2}".format(request['url'], request['version'], _val)
    return _s
         
def request_parser(message):
    """
    Given a message received from a connected client, determine if it is a valid HTTP request.
    @param message: Client HTTP request. 
    @return: Hash of valid URI fields.
    @return: None upon encountering an error.
    """
    # Breakdown of regex:        GET      AbsoluteURL (per rfc)        HTTP version            Everything else.
    regex = re.compile(r"""(?P<method>\w+) (?P<url>http.*) (?P<version>HTTP/\d\.\d)\r*\n*(?P<headers>.*)\r*\n""", re.DOTALL)
    match = regex.match(message)
    if match is not None:
        _method = match.group('method')
        _url = match.group('url')
        _version = match.group('version')
        _headers = match.group('headers')
        
        if 'GET' in _method:
            return {'method':_method, 'url':urlparse(_url)[2], 'version':_version, 'headers': _headers, 'host': urlparse(_url)[1]}
        else:
            return {'error': "Error 501: Not Implemented"}
    else:
        return {'error': "Error 400: Bad Request"}
      

            
def is_cached(filename):
    filename = filename.partition("/")[2] 
    print filename 
    fileExist = "false"
    file_to_use = "/" + filename
    print file_to_use

if __name__ == '__main__':
    main()
 


