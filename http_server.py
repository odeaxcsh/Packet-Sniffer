import http.server
import socketserver
from threading import Thread
from sys import argv

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory='srcs', **kwargs) 

if __name__ == '__main__':
    if len(argv) == 1:
        address = '127.0.0.1'
        port = 80
    elif len(argv) == 2:
        address = argv[1]
    elif len(argv) == 3:
        address = argv[1]
        port = int(argv[2])
    else:
        print("Invalid arguments -- Usage: http_server.py <IP> <PORT>")
        exit(1)

    http_server_ = socketserver.TCPServer((address, port), Handler)
    print("Running of {}:{}".format(address, port))
    http_server_.serve_forever()