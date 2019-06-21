import socket

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9001

BANNER = bytes('Vully the basic chat application', 'utf-8')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))

while True:
    s.listen()
    conn, addr = s.accept()
    with conn:
        conn.sendall(BANNER)