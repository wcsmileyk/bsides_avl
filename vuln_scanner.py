import socket
import ipaddress
from threading import Thread


def get_banner(ip_addr, port):
    try:
        s = socket.socket()
        s.connect((ip_addr, port))
        banner = s.recv(1024)
        print(f'Obtained banner from {ip_addr}')
        return banner.decode('utf-8')
    except:
        return


def check_banner(ip_addr):
    vuln_string = 'Vully the basic chat application'

    banner = get_banner(ip_addr, 9001)

    if banner:
        if banner.startswith(vuln_string):
            print(f'{ip_addr} running vully')


if __name__ == '__main__':
    ip_addrs = [str(ip) for ip in ipaddress.IPv4Network('192.168.1.0/24')]

    threads = []

    print('Starting Scan')

    for ip_addr in ip_addrs:
        t = Thread(target=check_banner, args=(ip_addr,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    print('Completed Scan')
