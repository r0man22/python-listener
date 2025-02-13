import os
import paramiko
import socket
import sys
import threading

# RSA Anahtar Dosyasını Yükle
CWD = os.path.dirname(os.path.realpath(__file__))
HOSTKEY = paramiko.RSAKey(filename=os.path.join(CWD, 'test_rsa.key'))

# SSH Sunucu Arayüzü
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if username == 'roman' and password == 'sekret':
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

if __name__ == '__main__':
    server = '192.168.1.19'
    ssh_port = 2222

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((server, ssh_port))
        sock.listen(100)
        print('[+] Listening for connection ...')

        client, addr = sock.accept()
        print(f'[+] Connection established from {addr}')
    
    except Exception as e:
        print(f'[-] Listen failed: {e}')
        sys.exit(1)

    try:
        bhSession = paramiko.Transport(client)
        bhSession.add_server_key(HOSTKEY)
        server = Server()
        bhSession.start_server(server=server)

        chan = bhSession.accept(20)
        if chan is None:
            print('*** No channel.')
            sys.exit(1)

        print('[+] Authenticated!')
        chan.send('Welcome to bh_ssh'.encode())

        while True:
            command = input("Enter command: ")
            if command.lower() == 'exit':
                chan.send('exit'.encode())
                print('Exiting...')
                bhSession.close()
                break
            
            chan.send(command.encode())
            response = chan.recv(8192)
            print(response.decode())

    except KeyboardInterrupt:
        print("\n[!] Server shutting down.")
        bhSession.close()
    except Exception as e:
        print(f'[!] Error: {e}')
        bhSession.close()
