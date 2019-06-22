import socket

HOST = socket.gethostbyname(socket.gethostname())
PORT = 9001

BANNER = bytes('Vully the basic chat application', 'utf-8')

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))

print('Starting Vully')

while True:
    s.listen()
    conn, addr = s.accept()
    with conn:
        print(addr)
        conn.sendall(BANNER)
