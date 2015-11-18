# -*- coding: utf-8 -*-

import random
import socket
import time

target_host = ("127.0.0.1", 1234)
best_input = b"Z"*20


def mutate(data):
    flip_index = random.randint(0, len(data) - 1)
    flip_value = random.randint(0, 255)
    return b"%s%s%s" % (data[:flip_index], bytes([data[flip_index] ^ flip_value]), data[flip_index + 1:])


cov_sock = socket.socket()
cov_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
cov_sock.bind(("127.0.0.1", 5678))
cov_sock.listen(1)
conn, _ = cov_sock.accept()
conn_f = conn.makefile()

while True:
    with socket.socket() as target_sock:
        try:
            target_sock.settimeout(4)
            target_sock.connect(target_host)
            fuzz_input = mutate(best_input)
            target_sock.send(fuzz_input)
            cov_data = conn_f.readline()
            if cov_data[:3] == "INC" or (cov_data[:3] == "EQU" and int(cov_data[4:]) > 0):
                print("New edge discovered with input: %s" % fuzz_input)
                best_input = fuzz_input
        except socket.error as se:
            print("Socket error: %s" % se)
            time.sleep(3)

cov_sock.close()