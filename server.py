import socket
import sys
import threading

from ecdh import *

BUFFER_SIZE = 4096
FORMAT = 'utf-8'


class Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.serv_cred = None

        # create a socket
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # make addresses reusable
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # dictionary of connected sockets and their public keys
        self.connection_dic = {}
        self.whisper_dic = {}

        # list of usernames
        self.client_names = []

    def run_server(self):

        # try to bind a socket
        try:
            self.server_socket.bind((self.host, self.port))
        except (socket.error, OverflowError, ValueError, OSError):
            print('\nSomething went wrong! Check IP and port.')
            sys.exit(0)

        # accept a queue of upcoming connections, a number of possible connections isn't specified
        self.server_socket.listen()

        print('Server is listening on %s:%s..' % (self.host, self.port))

        # get client's credentials
        self.get_client_cred()

    def get_client_cred(self):
        while True:
            # get client's info
            client, address = self.server_socket.accept()

            client_name = client.recv(BUFFER_SIZE).decode().lower()

            if client_name not in self.client_names:
                self.client_names.append(client_name)

                # add client to connection list
                if client not in self.connection_dic.keys():

                    client.send('DONE'.encode(FORMAT))

                    #
                    # DIFFIE HELLMAN
                    #
                    self.serv_cred = DH()

                    client.send(self.serv_cred.serialize_public())  # send serv public to client
                    print('\nServer public key sent')

                    client_public = client.recv(BUFFER_SIZE)  # get client pub
                    loaded_client_public = self.serv_cred.unserialize_public(client_public)  # load key from bytes
                    self.connection_dic[client] = loaded_client_public
                    self.whisper_dic[client] = client_name
                    print('Client public key loaded. All done.\n')

                    # print info message of new connection
                    print(f'{client_name} has connected from {address[0]}:{address[1]}')
                    # self.send_all(client, client_name, 'has connected', system=True)

                    welcome_msg = '\nConnection established!\n\n' \
                                  '!quit\t\texit from chat\n' \
                                  '!send [path]\tsend a document\n' \
                                  '@[username]\twhisper to specific user\n'

                    ciphertext = self.serv_cred.encrypt(
                        self.connection_dic[client],
                        welcome_msg
                    )

                    # send welcome message to client
                    client.send(ciphertext)

                    threading.Thread(
                        name="server_listener",
                        target=self.listener,
                        args=(client, client_name)
                    ).start()

                else:
                    client.send(b'ADDRESS_ALREADY_IN_USE')
                    print('\nSomething went wrong! The client address might be already in use.')
            else:
                client.send(b'USERNAME_ALREADY_IN_USE')

    def listener(self, current_client, client_name):
        while True:
            # listen for messages
            try:
                msg = current_client.recv(BUFFER_SIZE)
            except socket.error:
                # close connection when error
                print(f"{client_name} has left.")
                self.send_all(
                    current_client,
                    client_name,
                    'has left',
                    system=True
                )
                current_client.close()
                self.connection_dic.pop(current_client)
                self.whisper_dic.pop(current_client)
                break

            if msg != '':

                plaintext = self.serv_cred.decrypt(
                    self.connection_dic.get(current_client),
                    msg
                ).decode(FORMAT)

                if plaintext.startswith('@'):
                    self.whisper_to(
                        client_name,
                        plaintext
                    )
                    print('back from whisper')
                else:
                    self.send_all(
                        current_client,
                        client_name,
                        plaintext
                    )

                # print(client_name, 'says', msg)
                print(client_name, 'says', plaintext)

    def whisper_to(self, client_name, plaintext):
        print('IN WHISPER')

        receiver = plaintext[1:].split()[0]
        receiver_len = len(plaintext[1:].split()[0]) + 1
        msg = plaintext[receiver_len:].strip()

        common_keys = self.connection_dic.keys() & self.whisper_dic.keys()

        if receiver in self.whisper_dic.values():
            for c in common_keys:
                if self.whisper_dic[c] == receiver:
                    prep_msg = f"{client_name} @ "
                    prep_msg += msg
                    ciphertext = self.serv_cred.encrypt(self.connection_dic[c], prep_msg)
                    c.send(ciphertext)
        else:
            print('send error to client')

    def send_all(self, current_client, client_name, plaintext, system=False):
        for client, pub_k in self.connection_dic.items():
            if client != current_client:
                if system:
                    prep_msg = f"{client_name} "
                else:
                    prep_msg = f"{client_name} > "
                prep_msg += plaintext
                ciphertext = self.serv_cred.encrypt(pub_k, prep_msg)
                client.send(ciphertext)


server = Server('127.0.0.1', 5551)
server.run_server()

# if len(sys.argv) != 3:
#     print("\nPlease provide an IP address and a port number\nExample: python server.py 127.0.0.1 5551")
#     sys.exit(0)
# else:
#     try:
#         # takes the first argument from command prompt as IP address
#         host = str(sys.argv[1])
#
#         # takes second argument from command prompt as port number
#         port = int(sys.argv[2])
#     except ValueError as err:
#         print("\nSomething went wrong! Check IP and port. \n")
#         sys.exit(0)
#
#     server = Server(host, port)
#     server.run_server()
