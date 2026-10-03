from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization


import argparse
import base64
import binascii
import hashlib
import secrets
import socket
import sys
import time


# "Constants"
BUFFER_SIZE = 255
SOCKET_TIMEOUT_SECONDS = 15
SOCKET_PORT_MINIMUM = 1
SOCKET_PORT_MAXIMUM = 65535


def generate_ephemeral_x25519_keypair():
    """
    Generates and returns an x25519 keypair.

    @returns An x25519 keypair.
    """
    return x25519.X25519PrivateKey.generate()


def serialize_x25519_pubkey(
    the_pubkey):
    """
    Serializes and returns an x25519 public key as a byte string.

    @returns The x25519 public key, as a byte string.
    """
    return the_pubkey.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw)


def serialize_x25519_privkey(
    the_privkey):
    """
    Serializes and returns an x25519 private key as a byte string.

    @returns The x25519 private key, as a byte string.
    """
    return the_privkey.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
        encryption_algorithm=serialization.NoEncryption())


def compute_shared_secret(
    the_keypair,
    the_pubkey_bytes):
    """
    Computes the shared x25519 secret using the client's public and private
    keypair and the server's public key.

    @returns The shared secret, as a byte string
    """
    peer_pubkey = x25519.X25519PublicKey.from_public_bytes(the_pubkey_bytes)
    shared_secret = the_keypair.exchange(peer_pubkey)
    return shared_secret


def hash_secret_into_key(
    args,
    the_shared_secret):
    """
    Uses sha256 to hash a shared secret into a fixed with key

    @note Hashing this passphrase into a key does not require any 
    particular security considerations since the key, regardless,
    is only as good as the passphrase itself. In practice, this
    key (an AES-XTS-256 key) will be encrypted via an ephemeral
    AES-GCM-256 session key and send to the remote keyserver, where
    it will be loaded into a hardware accelerator and used
    unconditionally to perform encryption/decryption operations.
    In other words, this key is never "stored" or used for
    "authentication," and thus the hashed secret (i.e., the key)
    requires no special anti-cracking considerations.

    @returns A 32-byte (256-bit) key.
    """
    # Copy the key
    key = the_shared_secret

    # If hashing was requested (i.e., if "raw" was _not_ 
    # requested, since hashing is the default), hash the 
    # passphrase into a 256-bit key
    if None is args or not args.raw:
        hash_context = hashlib.sha256()
        _ = hash_context.update(the_shared_secret)
        key = hash_context.digest()
        
    return key


def setup_client():
    """
    Prepares the client by generating an ephemeral x25519 keypair
    and collecting ephemeral server data (i.e., IPv4 address and port).

    @raises Exception on invalid IPv4 string or port (i.e., a port outside
    of the inclusive range [1SOCKET_PORT_MINIMUM, SOCKET_PORT_MAXIMUM]).

    @returns A tuple containing: (1) the IPv4 server address, as a string;
    (2) the server port, as a string; (3) the ephemeral keypair, as the
    verbatim result of `x25519.X25519PrivateKey.generate()`.
    """
    server_address = ""
    server_port = ""

    # Generate and print the public key
    keypair = generate_ephemeral_x25519_keypair()
    print("Client public x25519 key (base64 encoded): {}".format(
        base64.b64encode(serialize_x25519_pubkey(keypair.public_key()))))

    # Block until the user hits 'Enter'
    print("Copy public key into IPXE bootloader keyserver command and launch keyserver")
    _ = input("Once keyserver is awaiting packets, hit ENTER to continue")

    # Gather and validate the IP/port are plausible
    server_addr = input("Enter the destination server IPv4 address: ")
    server_port = input("Enter the destination server port: ")

    # Validate address is plausible
    try:
        socket.inet_aton(server_addr)
    except socket.error:
        raise Exception("Determined '{}' is not a valid IPv4 string.".format(server_addr))

    # Validate port is plausible
    try:
        port_int = int(server_port)

        # Raise a dummy exception here to trigger the `except` block
        if (SOCKET_PORT_MINIMUM > port_int) or (SOCKET_PORT_MAXIMUM < port_int):
            raise Exception("")
    except Exception:
        raise Exception("Determined '{}' is not a valid (i.e., [1, 65536]) port...".format(server_port))

    return (server_addr, server_port, keypair)


def connect_to_keyserver(
    the_socket,
    server_addr,
    server_port,
    client_keypair):
    """
    "Connects" to the keyserver located at `server_addr:server_port`
    by sending the client's x25519 public key, subsequently waiting
    for the server's x25519 public key as a response.

    Note: Since the server already has the client's x25519 public key
    (as it must be supplied out-of-band by the user), this is really
    only a means of allowing the server to identify a potential
    client source address/port with ease (i.e., it has no "security
    relevance" here).

    @param  the_socket:     
                            The socket to send and receive data and
                            "acknowledgements" on (assumed to already
                            be set up as a UDP socket with correct
                            destination and port).

    @param  server_addr:    
                            A string represnetation of the IPv4 
                            server address where packets
                            will be sent to.

    @param  server_port:    
                            A string represnetation of the
                            server port where packets
                            will be sent to.

    @param  client_keypair:     
                            The client's public and private keypair,
                            as returned via
                            `generate_ephemeral_x25519_keypair()`.

    @returns The server's x25519 public key, as a byte string.
    """
    # Debug messages
    print("Connecting to keyserver at '{}:{}'".format(server_addr, server_port))

    # Send the client's x25519 public key to the destination server
    message = serialize_x25519_pubkey(client_keypair.public_key())
    bytes_sent = the_socket.sendto(
        message,
        (server_addr, int(server_port)))
    if len(message) != bytes_sent:
        raise Exception("Send failed (sent '{}/{}' bytes)".format(
            bytes_sent,
            len(message)))

    # Receive the server's public key as a response
    print("Waiting for keyserver's public x25519 key...")
    data, addr = the_socket.recvfrom(4096)
    if not data:
        raise Exception("Received no data...")

    # Debug messages
    print("Server public x25519 key (raw): '{}'...".format(binascii.hexlify(data)))
    server_public_key = data

    return server_public_key


def compute_shared_key(
    args,
    client_keypair,
    server_pubkey):
    """
    Computes and returns the shared ephemeral session key based on
    the supplied client keys (public and private) and the server's
    public key, returning the 256-bit key for subsequent use as an
    AES-GCM-256 key.

    @param  args:  
                            The verbatim argparse returned namespace

    @param  client_keypair:     
                            The client's public and private keypair,
                            as returned via
                            `generate_ephemeral_x25519_keypair()`.

    @param  server_pubkey:     
                            The server's x25519 public key, as a byte
                            string.

    @returns A 32-byte (256-bit) byte string representation of the
    ephemeral session key.
    """
    # Compute the shared secret using the client and server
    # public keys
    shared_secret = compute_shared_secret(client_keypair, server_pubkey)
    if args.verbose:
        print("Shared secret: '{}'".format(binascii.hexlify(shared_secret)))

    # Hash the secret into an actual key to add entropy and
    # ensure appropriate key size for subsequent AES-GCM-256 
    # operation
    #
    # Note: Since the public keys (and thus the shared secret)
    # are randomly generated and ephemeral, this is mostly a
    # convenience step, as opposed to an explicit security
    # measure
    aes_key = hash_secret_into_key(None, shared_secret)
    if args.verbose:
        print("Shared AES-GCM-256 session key: '{}'".format(binascii.hexlify(aes_key)))

    return aes_key

def generate_and_send_aes_iv(
    the_socket,
    server_addr,
    server_port):
    """
    Generates a random 12-byte IV and sends it to the remote keyserver
    for use as part of the AES-GCM-256 algorithm, returning the key
    as a bytestring for subsequent use by the client.

    @param  the_socket:     
                            The socket to send and receive data and
                            "acknowledgements" on (assumed to already
                            be set up as a UDP socket with correct
                            destination and port).

    @param  server_addr:    
                            A string represnetation of the IPv4 
                            server address where packets
                            will be sent to.

    @param  server_port:    
                            A string represnetation of the
                            server port where packets
                            will be sent to.

    @returns The 12-byte IV, as a bytestring.
    """
    # Generate a random IV for the AES-GCM-256 algorithm and
    # send it to the server
    aes_iv = secrets.token_bytes(12)
    print("Sending IV of '{}' to server at '{}:{}'".format(
        binascii.hexlify(aes_iv),
        server_addr, server_port))
    bytes_sent = the_socket.sendto(
        aes_iv,
        (server_addr, int(server_port)))
    if len(aes_iv) != bytes_sent:
        raise Exception("Send failed (sent '{}/{}' bytes)".format(
            bytes_sent,
            len(aes_iv)))

    print("Waiting for keyserver confirmation of receipt...")
    data, addr = the_socket.recvfrom(4096)
    if not data:
        raise Exception("Received no data...")
    print("Keyserver successfully received IV...")

    return aes_iv


def send_storage_key_to_keyserver(
    args,
    the_socket,
    server_addr,
    server_port,
    aes_key,
    aes_iv):
    """
    Hashes a passphrase (provided by user input) into an AES-XTS-256 key,
    encrypts the key using previously established (via ephemeral ECDHE)
    AES-GCM-256 key, and sends it to the remote keyserver.

    @param  args:  
                            The verbatim argparse returned namespace
    @param  the_socket:     
                            The socket to send and receive data and
                            "acknowledgements" on (assumed to already
                            be set up as a UDP socket with correct
                            destination and port).

    @param  server_addr:    
                            A string represnetation of the IPv4 
                            server address where packets
                            will be sent to.

    @param  server_port:    
                            A string represnetation of the
                            server port where packets
                            will be sent to.

    @param  aes_key:        A byte string containing the ephemeral
                            AES-GCM-256 session key, which will be 
                            used to encrypted the hashed passphrase
                            (i.e., the AES-XTS-256 key) before
                            sending it to the remote keyserver.

    @param  aes_iv:         A byte string containg the ephemeral 
                            AES-GCM-256 IV.
    """
    # Use a "passphrase" as an example of how one could trivially
    # turn a passphrase into a valid AES-XTS-256 key
    passphrase = input("Enter your passphrase: ")
    hashed_passphrase = hash_secret_into_key(args, passphrase.encode(encoding="utf-8"))
    if args.verbose:
        print("Decrypted AES-XTS-256 key: '{}'".format(binascii.hexlify(hashed_passphrase)))

    # Encrypt the hashed passphrase (now an AES-XTS-256 key) using the
    # ephemeral AES-GCM-256 key and IV
    aesgcm = AESGCM(aes_key)
    nonce = aes_iv
    ciphertext = aesgcm.encrypt(nonce, hashed_passphrase, b"")

    # Send the encrypted key to the keyserver
    print("Sending encrypted AES-XTS-256 key of '{}' to server at '{}:{}'".format(
        binascii.hexlify(ciphertext),
        server_addr, server_port))
    bytes_sent = the_socket.sendto(
        ciphertext,
        (server_addr, int(server_port)))
    if len(ciphertext) != bytes_sent:
        raise Exception("Send failed (sent '{}/{}' bytes)".format(
            bytes_sent,
            len(ciphertext)))

    print("Waiting for keyserver confirmation of receipt...")
    data, addr = the_socket.recvfrom(4096)
    if not data:
        raise Exception("Received no data...")
    print("Keyserver successfully received encrypted AES-XTS-256 key...")

    return

def main():
    retval = -1

    # Handle argument parsing
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-v", "--verbose",
        help="Enable verbose logging (WARNING: displays secrets in plaintext)",
        action="store_true",
        default=False)
    parser.add_argument(
        "-r", "--raw",
        help="Send the passphrase in raw form (unhashed, but encrypted)",
        action="store_true",
        default=False)
    args = parser.parse_args()

    # Open a UDP socket
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            # Set the socket timeout and bind to all ports
            # (this will be overwritten via subsequent UDP
            # sends)
            s.settimeout(SOCKET_TIMEOUT_SECONDS)
            s.bind(("0.0.0.0", 0))
            
            # Set up the client based on use inputs
            (server_addr, server_port, client_keypair) = setup_client()

            # "Connect" to the keyserver and receive its public key
            server_pubkey = connect_to_keyserver(
                s,
                server_addr,
                server_port,
                client_keypair)

            # Compute the shared AES-GCM-256 key
            aes_key = compute_shared_key(
                args,
                client_keypair,
                server_pubkey)

            # Send the server the IV
            aes_iv = generate_and_send_aes_iv(s, server_addr, server_port)
            
            # Using the AES key and IV, encrypt and send a hashed password
            # to the keyserver
            send_storage_key_to_keyserver(args, s, server_addr, server_port, aes_key, aes_iv)

        except socket.timeout:
            print("No message within '{}' seconds...".format(SOCKET_TIMEOUT_SECONDS))

        except Exception as e:
            print("Received exception '{}'. Failing...".format(e))

        print("Client done...")

if __name__ == "__main__":
    main()