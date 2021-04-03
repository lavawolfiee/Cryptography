import socket
import struct
import sys


def send_msg(sock, msg):
    """
    Send 4 bytes with length of message and then message
    """
    msg = struct.pack('>I', len(msg)) + msg
    sock.sendall(msg)


def recv_msg(sock):
    """
    Receive length of message in first 4 bytes and then receive
    the message of this length
    """
    raw_msglen = recvall(sock, 4)
    if not raw_msglen:
        return None
    msglen = struct.unpack('>I', raw_msglen)[0]

    return recvall(sock, msglen)


def recvall(sock, n):
    """
    Helper function to recv n bytes or return None if EOF is hit
    """
    data = bytearray()
    while len(data) < n:
        packet = sock.recv(n - len(data))
        if not packet:
            return None
        data.extend(packet)
    return data


class Server:
    def __init__(self, port, cipher, name='Server', key_len=32):
        self.cipher = cipher
        self.key_len = key_len
        self.__key = self.cipher.generate_key(self.key_len)
        self.name = name
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.bind(('127.0.0.1', port))
        self.sock.listen(1)

    def loop(self):
        client, address = self.sock.accept()

        temp_key = self.cipher.generate_key(self.key_len)
        client.send(self.cipher.encrypt_bytes(self.__key, temp_key))
        encrypted_data = client.recv(self.key_len)
        client.send(self.cipher.decrypt_bytes(encrypted_data, temp_key))

        while True:
            enc_msg = recv_msg(client)
            msg = self.cipher.decrypt_bytes(enc_msg, self.__key). \
                decode('utf-8')
            print(msg)

            out_msg = self.name + "> " + input(self.name + "> ")
            enc_out_msg = self.cipher.encrypt_bytes(
                out_msg.encode('utf-8'), self.__key)
            send_msg(client, enc_out_msg)

    def close(self):
        self.sock.close()


class Client:
    def __init__(self, rhost, port, cipher, name='Client', key_len=32):
        self.cipher = cipher
        self.name = name
        self.key_len = key_len
        self.__key = None
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((rhost, port))

    def loop(self):
        temp_key = self.cipher.generate_key(self.key_len)

        encrypted_data = self.sock.recv(self.key_len)
        self.sock.send(self.cipher.encrypt_bytes(encrypted_data, temp_key))
        encrypted_data = self.sock.recv(self.key_len)
        self.__key = self.cipher.decrypt_bytes(encrypted_data, temp_key)

        while True:
            out_msg = self.name + "> " + input(self.name + "> ")
            enc_out_msg = self.cipher.encrypt_bytes(
                out_msg.encode('utf-8'), self.__key)
            send_msg(self.sock, enc_out_msg)

            enc_msg = recv_msg(self.sock)
            msg = self.cipher.decrypt_bytes(enc_msg, self.__key). \
                decode('utf-8')
            print(msg)

    def close(self):
        self.sock.close()
