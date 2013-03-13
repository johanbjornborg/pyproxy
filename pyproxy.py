import socket, sys, re, os, SocketServer, threading, logging, logging.config, datetime
import email.utils as eut
from urlparse import urlparse

# List of all accepted URI headers. Connection is omitted because it is always replaced with 'close' anyway.
header_fields = ['Accept', 'Accept-Charset', 'Accept-Encoding', 'Accept-Language', 'Accept-Datetime',
'Authorization', 'Cache-Control', 'Cookie', 'Content-Length', 'Content-MD5', 'Content-Type',
'Date', 'Expect', 'From', 'Host', 'If-Match', 'If-Modified-Since', 'If-None-Match', 'If-Range', 'If-Unmodified-Since',
'Max-Forwards', 'Pragma', 'Proxy-Authorization', 'Range', 'Referrer', 'TE', 'Upgrade', 'User-Agent', 'Via', 'Warning']    


class TCPRequestHandler(SocketServer.BaseRequestHandler):
    

    def handle(self):
        """
        Entry point for multi-processing. Uses the inherited class functions to obtain the client socket.
        Requests from client must come in the form of a valid URI.
        @see: build_uri(cli_request) for more information on URI formatting.
        """
        _message = self.request.recv(1024)
        cli_request = self.request_parser(_message)
        if 'error' not in cli_request:
            
            # Attempt to load from cache. If the file doesn't exist or is corrupt, throw an IOError exception
            # and reload from the remote server.
            try:
                
                f = open("cache/" + cli_request['host'] + cli_request['url'].replace("/", "-"), 'rb')         
                data = f.readlines()
                f.close()
                if self.cache_control(data):
                    # Data still good.
                    logging.info("Valid file exists in cache. Sending to client.")
                    for i in range(0, len(data)):
                        self.request.send(data[i])
                else:
                    logging.info("Invalid file exists in cache. Requesting new copy.")
                    raise IOError
                
            except IOError:
    
                try:
                    # Request is valid and not cached. Open a connection and retrieve the web page.
                    s = self.build_uri(cli_request)
                    outbound = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    logging.info("Client %s requested host %s" % (self.client_address, cli_request['host']))
                    outbound.connect((cli_request['host'], 80))
    
                    # Write the socket buffer to a temporary file, and then read those lines into a buffer.
                    try:
                        fileobj = outbound.makefile('r', 0)
                        print s
                        fileobj.write(s)
                       
                        buffer = fileobj.readlines()
                        print buffer
                        # Cache the result.                        
                        tmpFile = open("cache/" + cli_request['host'] + cli_request['url'].replace("/", "-"), 'wb')
                        
                        # Send the data to the requesting client.
                        for i in range(0, len(buffer)):
                            tmpFile.write(buffer[i])
                            self.request.send(buffer[i])
    
                        tmpFile.close()
                    except socket.timeout, e:
                        logging.error(str(e))
                        
                except Exception, e:
                    self.request.send(self.build_html_error("Error 400: Bad Request"))
                    logging.error(str(e))
                    
            # Close the client socket
            self.request.close() 
        else:
            logging.error("Client %s error: %s" % (str(self.client_address), cli_request['error']))
            self.request.send(self.build_html_error(cli_request['error']))
            self.request.close()
    
    def build_uri(self, request):
        """
        Takes a properly formatted HTTP request and returns the formatted URI request.
        Refer to RFC 1945 section 5.4.2 for details on how URI requests are formatted.
        @param request: Hash of a valid HTTP GET request.
        @return: A (hopefully) valid URI
        """  
        _headers = [(_h.split(':')[0].strip(), _h.split(':')[1].strip()) for _h in request['headers'].splitlines() if _h.split(':')[0] in header_fields]
        _headers.append(('Connection', 'close'))
        
        _val = "".join("%s: %s\r\n" % h for h in _headers)
            
        _val += "\r\n"
        
        # Form the URI request in its entirety. 
        if len(request['url']) > 1:
            _s = "GET http://{0} {1}\r\n{2}".format(request['host'] + request['url'], request['version'], _val)
        else:
            _s = "GET / {1}\r\n{2}".format(request['host'], request['version'], _val)
        return _s
             
    def request_parser(self, message):
        """
        Given a message received from a connected client, determine if it is a valid HTTP request.
        @param message: Client HTTP request. 
        @return: Hash of valid URI fields.
        @return: None upon encountering an error.
        """
        # Breakdown of regex:        GET      AbsoluteURL (per rfc)        HTTP version            Everything else.
        regex = re.compile(r"""(?P<method>\w+) (?P<url>.*) (?P<version>HTTP/\d\.\d)\r*\n*(?P<headers>.*)\r*\n""", re.DOTALL)
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
       
    def build_html_error(self, error_message):
        """
        Builds a very basic webpage string in the event of an error in between the client and proxy server. 
        @param error_message: String containing an HTTP error message.
        @return: Webpage readable string. 
        """
        return """<html><head></head><body><font size="20"><b>{0}</b></font></body></html>""".format(error_message)
    
    def cache_control(self, data):
        """
        Determines if the current file is still within the appropriate age to be considered valid.
        @param data: data buffer from a cached file 
        @return: True if cache file is still valid, false otherwise.
        """
        # List of good words and bad words. Bad words imply that the file must always be refreshed.
        _stopwords = ['no-cache', 'no-store', 'must-revalidate', 'proxy-revalidate']
        _gowords = ['max-age', 's-maxage']
        cache_control = [(d) for d in data if 'Cache-Control' in d]
        cache_control = '\n'.join(cache_control)

        for s in _stopwords or not cache_control:
            if s in cache_control:
                return False
        
        # Attempt to retrieve max-age from the cache-control field. 
        # Throws an exception if there is strange formatting (eg, not a number).
        max_age = None
        for g in _gowords:
            if g in cache_control:
                try:
                    max_age = int(cache_control.split('=')[1])
                except ValueError as e:
                    logging.error(str(e))
                    return False
        if not max_age:
            return False
        
        cached_date = [(datetime.datetime(*eut.parsedate(d[5:])[:6])) for d in data if 'Date:' in d]
        current_date = datetime.datetime.now()
        delta = (current_date - cached_date[0]).total_seconds()

        if max_age < delta:
            return False
        else:
            return True
     
class ThreadedTCPServer(SocketServer.ThreadingMixIn, SocketServer.TCPServer):
    """
    Overloaded constructor for a threadedTCPServer object. Template acquired via python.org's docs.
    """
    pass

if __name__ == '__main__':
    
    if len(sys.argv) <= 1:
        print 'Usage : "python pyproxy.py <server_port>"\n[server_port : It is the desired port for the Proxy Server]'
        sys.exit(2)
        
    elif len(sys.argv) == 3:
        # Turn logging to specified value.
        if 0 <= int(sys.argv[2]) <= 5:
            logging.basicConfig(level=int(sys.argv[2]) * 10)
            pass
        else:
            print "Logging Level: CRITICAL messages only."
            logging.basicConfig(level=50)
    else:
        # No parameter for logging, turn it to CRITICAL level.
        print "Logging Level: CRITICAL messages only."
        logging.basicConfig(level=10)
    
    # Clear cache prior to run (for testing/grading purposes.)
    filelist = [ f for f in os.listdir("./cache")]
    for f in filelist:
        os.remove("./cache/" + f)
    
    host = ''
    port = int(sys.argv[1])
    
    #Start serving requests...
    server = ThreadedTCPServer((host, port), TCPRequestHandler)
    ip, port = server.server_address
    
    # Start a thread with the server -- that thread will then start one more thread for each request
    server_thread = threading.Thread(target=server.serve_forever)
    server_thread.daemon = True
    server_thread.start()
    while True:
        continue
    
 


