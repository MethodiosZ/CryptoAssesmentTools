import socket
import ssl

def create_tls_connection(host, port):
    context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
    context.verify_mode = ssl.CERT_REQUIRED
    context.load_verify_locations('path/to/certfile.pem')

    with socket.create_connection((host, port)) as sock:
        with context.wrap_socket(sock, server_hostname=host) as ssock:
            print(f"TLS 1.2 connection established with {host}:{port}")
            print(f"Cipher: {ssock.cipher()}")
            print(f"Server certificate: {ssock.getpeercert()}")

if __name__ == "__main__":
    host = 'example.com'
    port = 443
    create_tls_connection(host, port)