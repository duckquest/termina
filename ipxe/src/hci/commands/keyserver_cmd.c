#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <ipxe/base64.h>
#include <ipxe/command.h>
#include <ipxe/keyserver.h>
#include <ipxe/parseopt.h>
#include <ipxe/socket.h>

#include <hci/ifmgmt_cmd.h>

#include <pxe.h>
#include <pxe_api.h>

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( PERMITTED );

// ***************************************************************************
/** @file
 *
 * keyserver command
 *
 */

/** "keyserver" options */
struct keyserver_options
{
    // Use verbose logging
    int verbose;

    // Use debug logging
    // (this logging is more transparent than "verbose"
    // logging and will even print shared secrets and
    // private keys, so it should only be used in test
    // environments and for debugging purposes, ideally
    // with fake passwords, so true password hashes
    // are not printed after decryption)
    int debug;

    // Allow for a keyserver connection timeout to be specified
    // (in seconds)
    uint32_t timeout_seconds;

	// Image name 
	char * image_command_line;

	// Kernel name 
	char * kernel_command_line;
};

/** "keyserver" option list */
static struct option_descriptor keyserver_opts[] =
{
    OPTION_DESC ("verbose", 'v', no_argument,
              struct keyserver_options, verbose, parse_flag),
    OPTION_DESC ("debug", 'd', no_argument,
              struct keyserver_options, debug, parse_flag),
    OPTION_DESC ("image_command_line", 'i', optional_argument,
			  struct keyserver_options, image_command_line, parse_string),
    OPTION_DESC ("kernel_command_line", 'k', optional_argument,
			  struct keyserver_options, kernel_command_line, parse_string),
    OPTION_DESC ("timeout_seconds", 't', required_argument,
              struct keyserver_options, timeout_seconds, parse_integer),
};

/** "keyserver" command descriptor */
static struct command_descriptor keyserver_cmd =
    COMMAND_DESC(struct keyserver_options, keyserver_opts, 1, 1, "<b64_encoded_client_x25519_pubkey>");


// ***************************************************************************
static keyserver_info_t g_keyserver = {0};


// ***************************************************************************
/**
 * The "keyserver" command
 *
 * @v argc      Argument count
 * @v argv      Argument list
 * @ret rc      Return status code
 */
static int keyserver_exec (int argc, char **argv)
{
    // Initialize variables
    struct keyserver_options opts;
    int rc = -1;
    char * ip_string = NULL;
    memset(&(g_keyserver), 0, sizeof(g_keyserver));
    memset(&(opts), 0, sizeof(opts));

    // Parse options
    if (0 != (rc = parse_options(argc, argv, &keyserver_cmd, &opts)))
    {
        printf("[x] Failed to parse options...\n");
        goto cleanup;
    }

    // Extract arguments
    (g_keyserver.timeout_seconds) = (int32_t) (opts.timeout_seconds);
    if (opts.verbose)
    {
        (g_keyserver.options) |= KEYSERVER_VERBOSE;
        printf("[*] Verbose printing enabled...\n");
    }
    if (opts.debug)
    {
        (g_keyserver.options) |= KEYSERVER_DEBUG;
        printf("[w] Debug printing enabled.\n"
               "[w] WARNING: Debug mode will print shared secrets "
               "and keys in PLAINTEXT\n");
    }
    if (opts.image_command_line)
    {
        (g_keyserver.initrd_command_line) = (opts.image_command_line);
    }
    if (opts.debug)
    {
        (g_keyserver.kernel_command_line) = (opts.kernel_command_line);
    }

    // Extract required arguments
    (g_keyserver.b64_client_pubkey) = (uint8_t *) argv[optind];
    (g_keyserver.b64_client_pubkey_len) = strlen(argv[optind]);

    // Configure the interface (if already configured,
    // internally, this becomes a no-op)
    if (0 != (rc = ifconf_exec(1, argv)))
    {
        printf("[x] Failed to configure interface...\n");
        goto cleanup;
    }
    printf("[*] Successfully configured interface!\n");

    // Display the IP and store it in the keyserver structure
    // for later use
    if (0 != (rc = get_and_print_ip(&ip_string)))
    {
        printf("[x] Failed to obtain and display active ip address...\n");
        goto cleanup;
    }
    (g_keyserver.ip_string) = ip_string;

    // Run the keyserver
    if (0 != keyserver(&g_keyserver))
    {
        printf("[x] Failed to run keyserver...\n");
        goto cleanup;
    }

    // Set success code
    rc = 0;

cleanup:
    // Free resources
    if (NULL != ip_string)
    {
        free(ip_string);
        ip_string = NULL;
    }

    return rc;
}

/** "keyserver" command */
COMMAND(keyserver, keyserver_exec);
