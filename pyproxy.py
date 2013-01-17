import socket, sys


def main():
    
    if len(sys.argv) <= 1:
        print 'Usage : "python ProxyServer.py server_ip"\n[server_ip : It is the IP Address Of Proxy Server'
        sys.exit(2)
    host = ''
    port = 80
    # Create a TCP socket connection, bind it to the specified port.
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host,port))
    server_socket.listen(5)
    
    #Start serving requests...
    while True:
        print "Ready to serve..."
        client_socket, client_address = server_socket.accept()
        print 'Received connection request from: ', client_address
        #TODO: Implement threading here.
        _message = client_socket.recv(1024)
        message = _message.split()
        if 'GET' in message[0]:
            method = message.split()[0]
            url = message.split()[1]
            http_ver = message.split()[2]
            
            # caching check.
            filename = url.partition("/")[2] 
            print filename 
            fileExist = "false"
            file_to_use = "/" + filename
            print file_to_use
            try:
                # Check whether the file exist in the cache
                f = open(file_to_use[1:], "r")
                outputdata = f.readlines()
                fileExist = "true"
                # ProxyServer finds a cache hit and generates a response message tcpCliSock.send("HTTP/1.0 200 OK\r\n") tcpCliSock.send("Content-Type:text/html\r\n")
                # Fill in start.
                # Fill in end.
            except IOError:
                # Do something here.
                break;
        else:
            print "Error: %s Not Implemented." % message[0]
            break
       
def uri_parser(message):
    pass

       

if __name__ == '__main__':
    main()
 


