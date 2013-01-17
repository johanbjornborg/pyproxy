import socket, sys, re, multiprocessing


            
def main():
    
    if len(sys.argv) <= 1:
        print 'Usage : "python pyproxy.py <server_ip>"\n[server_ip : It is the IP Address Of Proxy Server]'
        sys.exit(2)
    host = ''
    port = sys.argv[1]
        
    # Create a TCP socket connection, bind it to the specified port.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host,int(port)))
    server_socket.listen(5)
    
    #Start serving requests...
    while True:
        print "Ready to serve..."
        client_socket, client_address = server_socket.accept()
        print 'Received connection request from: ', client_address
        p = multiprocessing.Process(target=client_thread, args=(client_socket, client_address))
        p.start()
        p.join()
        

def client_thread(socket):
    #TODO: Implement threading here.
        _message = socket.recv(1024)
        request = request_parser(_message)
        if request is not None:
            # Request is valid. Perform appropriate action.
            build_uri(request)
            
            #Send request
            
            #Cache the results
            pass
        else:
            return None

def build_uri(request):
    """
    Takes a properly formatted HTTP request and returns the formatted URI request.
    Refer to RFC 1945 section 5.4.2 for details on how URI requests are formatted.
    @param request: Hash of a valid HTTP GET request.
    @return: Valid URI
    """
    return """%s / %s
Host: %s
Connection: close
%s
""" % request['method'], request['version'], request['url'], request['headers']
    pass
       
def request_parser(message):
    """
    Given a message received from a connected client, determine if it is a valid HTTP request.
    @param message: Client HTTP request. 
    @return: Hash of valid URI fields.
    @return: None upon encountering an error.
    """
    regex = re.compile(r"""(?P<method>\w+) (?<url>http.*) (?P<version>HTTP/\d\.\d) (?<headers>.*)""")
    match = regex.match(message)
    if match is not None:
        _method = match.group('method')
        _url = match.group('url')
        _version = match.group('version')
        _headers = match.group('headers')
        
        if 'GET' in _method:
            return {'method':_method, 'url':_url, 'version':_version, 'headers': _headers}
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
 


