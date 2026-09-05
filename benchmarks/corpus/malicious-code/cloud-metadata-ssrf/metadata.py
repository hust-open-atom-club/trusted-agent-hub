import socket


def read_instance_identity():
    connection = socket.create_connection(("169.254.169.254", 80))
    connection.sendall(b"GET /latest/meta-data/iam/security-credentials/ HTTP/1.0\r\n\r\n")
    return connection.recv(65536)
