import socket
import sys
import threading

from ecdh import *

BUFFER_SIZE = 4096
FORMAT = 'utf-8'


class Client:
    def __init__(self, host, port, name):
        self.host = host
        self.port = port
        self.client_name = name
        self.server_public = None
        self.client_cred = ECDH()

        # create socket
        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.connect()

    def connect(self):
        # try to connect to server
        try:
            self.client_socket.connect((self.host, self.port))
        # server is not running?
        except (ConnectionRefusedError, ConnectionAbortedError, ConnectionError, ConnectionResetError):
            print('\nUnable to connect to the server\n')
            sys.exit(0)

        # send username
        self.client_socket.send(self.client_name.encode(FORMAT))

        # get response
        msg = self.client_socket.recv(BUFFER_SIZE).decode(FORMAT)

        if not msg.startswith('DONE'):
            if msg == 'USERNAME_ALREADY_IN_USE':
                print('\nUsername already in use. Try again!')

            elif msg == 'ADDRESS_ALREADY_IN_USE':
                print('\nAddress already in use. Try again!')

            else:
                print('OTHER ERROR!')

            self.client_socket.close()
            sys.exit(0)

        else:

            server_public = self.client_socket.recv(BUFFER_SIZE)  # get server public
            loaded_client_public = self.client_cred.unserialize_public(server_public)  # load key from bytes
            self.server_public = loaded_client_public  # save server public
            print('\nServer public key loaded.')

            self.client_socket.send(self.client_cred.serialize_public())  # send client public to server
            print('Client public key sent. All done.\n')

            welcome_msg = self.client_socket.recv(BUFFER_SIZE)

            plaintext = self.client_cred.decrypt(
                self.server_public,
                welcome_msg
            ).decode(FORMAT)

            print(plaintext)

            # start thread listen for messages
            listen = threading.Thread(name="client_listener", target=self.listener)
            listen.start()

            # start thread waiting for input
            write = threading.Thread(name="client_writer", target=self.writer)
            write.start()

    def writer(self):
        while True:
            msg = input('')

            if msg.lower() == '!quit':
                print("\nSee ya, bye-bye")
                self.client_socket.close()
                sys.exit(0)

            if msg != '':
                ciphertext = self.client_cred.encrypt(
                    self.server_public,
                    msg
                )

                self.client_socket.send(ciphertext)

    def listener(self):
        while True:
            # listen for messages
            try:
                msg = self.client_socket.recv(BUFFER_SIZE)
                if msg != '':
                    plaintext = self.client_cred.decrypt(
                        self.server_public,
                        msg
                    ).decode(FORMAT)
                    print(plaintext)

            except ConnectionResetError:
                print("Server is shut down")
                self.client_socket.close()
                sys.exit(0)
            except ConnectionAbortedError:
                self.client_socket.close()
                sys.exit(0)


# client_name = input('Your name: ')
# client = Client('127.0.0.1', 5551, client_name)

if len(sys.argv) != 3:
    print("\nPlease provide an IP address and a port number\nExample: python server.py 127.0.0.1 5551")
    sys.exit(0)
else:
    try:
        # takes the first argument from command prompt as IP address
        host = str(sys.argv[1])

        # takes second argument from command prompt as port number
        port = int(sys.argv[2])
    except ValueError as err:
        print("\nSomething went wrong! Check IP and port. \n")
        sys.exit(0)

    client_name = input('Your name: ')
    client = Client(host, port, client_name)
