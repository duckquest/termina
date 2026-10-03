# Termina

Termina is an extension of the iPXE software (https://github.com/ipxe/ipxe), permitting secure transfer of cryptographic keys between cloud service users and a given target virtual machine, specifically through the use of a virtual network bootloader. While the best documentation on building virtual ROMs, bootable USBs, or floppies can be found in the original iPXE documentation (i.e., [ipxe-readme-me](ipxe-readme.md)), we provide sample Termina commands and expect outputs below.

# Termina Quick Usage

Termina has two primary components: (1) a user-side python client (this lives on the users workstation or point-of-access) and (2) a remote virtual network bootloader driver (this is purpose-built using the instructions found in [ipxe-readme-me](ipxe-readme.md)) or the build script found in [build-sh](build.sh))). After building the virtual bootloader driver and uploading it for use in the target virtual environment (e.g., VMware Workstation, VMware ESXi, etc.), follow the below commands to establish a secure session (using ECDHE and AES-GCM-256 cryptography) between the remote virtual machine and the local workstation.

## Establishing the Secure Channel

### Assumptions 

Note: As of this documentation, Termina mandates:

- Routability between component (1) and (2) via UDP traffic (i.e., UDP packets must be able to reach the virtual network bootloader from the user-side python client, and vice versa).

### Steps

1. First, start the `python3` user client by running `python3 ./client.py` (assuming you are in the top level directory of the termina repository).

2. The client will print an ephemeral, base64 encoded x25519 key. Copy this key and save it for step 5, but do not yet hit ENTER.

3. Now, after ensuring the network bootloader is first in the target virtual machine's boot sequence, power on the virtual machine.

4. At boot time on the virtual machine, be sure to press "CTRL + B" to enter the command menu.

5. While there are many native iPXE commands available, using Termina necessitates the use of the `keyserver` command, where a user should pass two parameters: (1) `-v` to print key validation information and (2) the base64 encoded key from step 2. Additional optional parameters exist and can be view by entering the `keyserver` command without any arguments. 

6. The keyserver will configure a local interface, print its relevant IPv4 address (obtained via DHCP at this time), open a promiscuous UDP socket, and print both its and the client's x25519 public keys. 

7. Now, on the `python3` client, hit `ENTER`, then: (1) enter the server's IPV4 address, (2) choose and enter a destination port to send packets to (note: since the keyserver is listening on a promiscuous UDP socket, any port is fine; packets not containing the user's public key will be dropped, so service should be fairly stable, although denial-of-service prevention is not a focus of Termina).

8. Assuming routability exists, debug messages will be printed demonstrating the set up of a secure channel between the `python3` client and the Termina bootloader server; however, to ensure prevention of man-in-the-middle attacks, before a user enters their passphrase (this is technically arbitrary data that will be sent through an ECDHE established, AES-GCM-256 secured channel, but in the context of Termina's original purpose, it would be a passphrase), they should confirm the received "Server public x25519 key (raw)" on the `python3` client matches the key output by the Termina bootloader. After confirming the keys match, a user can enter their passphrase (or arbitrary data) and examine debug messages to confirm proof-of-concept.

## Application

Notably, by using the above steps, coupled with a bit of clever massaging of files, a user can practically use the Termina software to provide secure key transfer (and loading) of LUKS passphrase for a given, encrypted virtual disk system. To do this, minimal changes are needed within the encrypted guest system; below, we outline how this can be accomplished with an already-encrypted Ubuntu 20.04 guest system.

### /etc/crypttab 

Assuming a user already possess a LUKS-encrypted Ubuntu 20.04 virual machine, Termina integration can be conducted by adding the below line to their `/etc/crypttab` file

```
sda6_crypt UUID=<uuid> none luks,keyscript=/etc/echo-luks
```

### /etc/echo-luks

Now, a user can modify their `/etc/echo-luks` to extract a parameter titled `passphrase` from the kernel command line by creating the following `etc/echo-luks` file

```
cmdline=$(cat /proc/cmdline)

val="invalid"
for param in $cmdline; do
	case $param in
		passphrase=*)
			val="${param#*=}"
			echo -n "$val"
			;;
	esac
done
```

### Image and Kernel

To permit Termina (a network bootloader) to boot one's image, a user should host their generic virtual machine's kernel and initrd in an http, network accessible location. In this example, we use the following pseudo-locations are used:

(1) http://1.2.3.4:8080/initrd.img

(2) http://1.2.3.4:8080/vmlinuz

### Putting it all together

Now, the below steps can be used to boot the encrypted virtual machine without requiring user input via the virtual interface (which could be used to sniff sensitive data if the cloud service provider were malign). 

1. First, start the `python3` user client by running `python3 ./client.py` (assuming you are in the top level directory of the termina repository).

2. The client will print an ephemeral, base64 encoded x25519 key. Copy this key and save it for step 5, but do not yet hit ENTER.

3. Now, after ensuring the network bootloader is first in the target virtual machine's boot sequence, power on the virtual machine.

4. At boot time on the virtual machine, be sure to press "CTRL + B" to enter the command menu.

5. While there are many native iPXE commands available, using Termina necessitates the use of the `keyserver` command, where a user should pass four parameters: (1) `-v` to print key validation information, (2) the path to the user's network hosted `initrd.img` file (e.g., `-i initrd:http://1.2.3.4:8080/initrd.img`), (3) the path to the user's network hosted kernel, along with the kernel command line, using `:` instead of spaces, where applicable (e.g., `-k kernel:http://1.2.3.4:8080/vmlinuz:root=/dev/mapper/vgubuntu-root:ro:quiet:splash`), and (4) the base64 encoded key from step 2. Additional optional parameters exist and can be view by entering the `keyserver` command without any arguments.

6. The keyserver will configure a local interface, print its relevant IPv4 address (obtained via DHCP at this time), open a promiscuous UDP socket, and print both its and the client's x25519 public keys. 

7. Now, on the `python3` client, hit `ENTER`, then: (1) enter the server's IPV4 address, (2) choose and enter a destination port to send packets to (note: since the keyserver is listening on a promiscuous UDP socket, any port is fine; packets not containing the user's public key will be dropped, so service should be fairly stable, although denial-of-service prevention is not a focus of Termina).

8. Assuming routability exists, debug messages will be printed demonstrating the set up of a secure channel between the `python3` client and the Termina bootloader server; however, to ensure prevention of man-in-the-middle attacks, before a user enters their passphrase (this is technically arbitrary data that will be sent through an ECDHE established, AES-GCM-256 secured channel, but in the context of Termina's original purpose, it would be a passphrase), they should confirm the received "Server public x25519 key (raw)" on the `python3` client matches the key output by the Termina bootloader. After confirming the keys match, a user can enter their passphrase (or arbitrary data) and examine debug messages to confirm proof-of-concept.

Note: Termina was designed with the assumption a user is using encrypted memory solutions (e.g., AMD SEV), thus, the primary concern is transfering of secure data to memory, after which security is delegated to the hardware.

# Research

While there are many improvements we would like to make to the software, the Termina proof-of-concept is functional, and we welcome and encourage repository forks and extensions. Stay tuned for relevant technical research papers, where much more information will be published, when appropriate.