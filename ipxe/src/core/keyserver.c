FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( PERMITTED );


#include <errno.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>


#include <ipxe/aes.h>
#include <ipxe/base64.h>
#include <ipxe/crypto.h>
#include <ipxe/ecdhe.h>
#include <ipxe/gcm.h>
#include <ipxe/in.h>
#include <ipxe/keyserver.h>
#include <ipxe/parseopt.h>
#include <ipxe/rbg.h>
#include <ipxe/settings.h>
#include <ipxe/sha256.h>
#include <ipxe/timer.h>
#include <ipxe/x25519.h>


// ***************************************************************************
/**
    @brief Opens a promiscuous UDP socket and runs the keyserver by: (1) 
    waiting for a client to reach out, (2) establishing an ephemeral
    AES-GCM-256 key via x25519 ECDHE, (3) receiving an AES-XTS-256 key
    via encrypted UDP traffic, and (4) "loads the AES-XTS-256 key into
    a hardware accelerator for non-volatile storage" (this step is in quotes
    because it is only theoretical, since no such system necessarily exists
    and this code is a proof-of-concept).
 
    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver completion, otherwise `-1`.
*/
int keyserver(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    int retval = -1;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }

    // Open a UDP socket in promiscuous mode
    if (PXENV_EXIT_SUCCESS != open_promiscuous_udp_socket(the_keyserver))
    {
        printf("[x] Failed to open promiscuous UDP socket...\n");
        goto cleanup;
    }
    printf("[*] Successfully opened promiscuous UDP socket...\n");

    // Handle the keyserver state machine
    if (0 != keyserver_process_state(
        the_keyserver))
    {
        printf("[x] Keyserver failed to complete...\n");
        goto cleanup;
    }

    printf("[*] Keyserver successfully completed...\n");
    retval = 0;

cleanup:
    // Close the socket (if it has not been opened, internally,
    // this becomes a no-op, returning `PXENV_EXIT_SUCCESS`)
    if (PXENV_EXIT_SUCCESS != close_promiscuous_udp_socket(the_keyserver))
    {
        printf("[x] Failed to close promiscuous UDP socket...\n");
        retval = -1;
    }
    else
    {
        printf("[*] Successfully closed promiscuous UDP socket...\n");
    }

    return retval;
}


// ***************************************************************************
/**
    @brief Handles state traversal based on messages received (or not
    received).
 
    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver completion, otherwise `-1`.
*/
int keyserver_process_state(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    int retval = -1;
    int is_done = 0;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }

    // Continuously loop until we are done, or
    // an error has occurred
    while (0 == is_done)
    {
        // Based on the state, perform specific handling
        switch (the_keyserver->server_state)
        {
            // For every state, a non-zero return code is considered a
            // failure; otherwise, after handling, we break the case and
            // allow internal state maintenance to determine the next
            // steps
            case KEYSERVER_INIT:
                if (0 != keyserver_process_state_init(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_INIT'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_WAITING_FOR_AUTHENTICATION:
                if (0 != keyserver_process_state_waiting_for_authentication(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_WAITING_FOR_AUTHENTICATION'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_WAITING_FOR_IV:
                if (0 != keyserver_process_state_waiting_for_iv(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_WAITING_FOR_IV'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_WAITING_FOR_DISK_KEY:
                if (0 != keyserver_process_state_waiting_for_disk_key(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_WAITING_FOR_DISK_KEY'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_DECRYPTING_DISK_KEY:
                if (0 != keyserver_process_state_decrypting_disk_key(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_DECRYPTING_DISK_KEY'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_BOOT:
                if (0 != keyserver_process_state_boot(the_keyserver))
                {
                    printf("[x] Failed to process state "
                           "'KEYSERVER_BOOT'...\n");
                    goto cleanup;
                }
                break;
            case KEYSERVER_COMPLETE:
                printf("[*] AES-XTS-256 key loaded into hardware accelerator. "
                       "Enter `exit` to boot with encrypted non-volatile storage...\n");
                is_done = 1;
                break;
            default:
                printf("Received unknown or unsupported "
                       "state ('%d')...\n",
                       (int) the_keyserver->server_state);
                goto cleanup;
        }
    }

    // Indicate success
    retval = 0;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Handles the initialization state of the keyserver by: (1) decoding
    the user-input x25519 public key of the client, (2) generating a public
    and private x25519 keypair, (3) computing the x25519 shared secret, and
    (4) hashing the shared secret (via sha256) into a 256-bit key, which
    will later be used as the ephemeral AES-GCM-256 key.
 
    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver initialization, otherwise `-1`.
*/
int keyserver_process_state_init(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    struct x25519_value private_key;
    struct x25519_value public_key;
    struct x25519_value partner_key;
    struct x25519_value shared_secret;
    uint8_t temp_decoded_key[KEYSERVER_DEFAULT_ECDHE_KEY_LEN << 1];
    size_t temp_decoded_key_len = 0;
    int retval = -1;

    // In general this type of stack allocation is not wise, but we permit
    // it here only because it is in keeping with the IPXE code base and
    // `sha256_algorithm` is itself statically defined for this express purpose
    struct digest_algorithm * sha256_digest = (struct digest_algorithm *) &sha256_algorithm;
    uint8_t sha256_ctx[sha256_digest->ctxsize];
    uint8_t sha256_out[sha256_digest->digestsize];

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    // Clear/initialize key structures
    memset(temp_decoded_key, 0, sizeof(temp_decoded_key));
    memset(&(the_keyserver->client_pubkey), 0, sizeof(the_keyserver->client_pubkey));
    memset(&(the_keyserver->server_pubkey), 0, sizeof(the_keyserver->server_pubkey));
    memset(&(the_keyserver->server_private_key), 0, sizeof(the_keyserver->server_private_key));
    memset(&private_key, 0, sizeof(private_key));
    memset(&public_key, 0, sizeof(public_key));
    memset(&partner_key, 0, sizeof(partner_key));
    memset(&shared_secret, 0, sizeof(shared_secret));

    // B64 decode the pubkey and copy it into the
    // output parameter, on success
    printf("[*] Decoding b64 encoded client x25519 public key of: '%s'\n",
        (the_keyserver->b64_client_pubkey));
    temp_decoded_key_len = base64_decode(
        (const char *) (the_keyserver->b64_client_pubkey),
        (char *) temp_decoded_key,
        (size_t) sizeof(temp_decoded_key));
    if (KEYSERVER_DEFAULT_ECDHE_KEY_LEN != temp_decoded_key_len)
    {
        printf("[x] Failed to decode client x25519 public key\n");
        goto cleanup;
    }
    memcpy(&(partner_key.raw), temp_decoded_key, temp_decoded_key_len);
    print_hex_helper(
        the_keyserver,
        !KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Decoded client x25519 public key of: '",
        "'",
        (partner_key.raw),
        (uint32_t) sizeof(partner_key));

    // Generate server's ECDHE private key
    if (0 != rbg_generate(
        NULL,
        0,
        0,
        &(private_key.raw),
        sizeof(private_key)))
    {
        printf("[x] Failed to generate private server key "
               "bytes...\n");
        goto cleanup;
    }
    print_hex_helper(
        the_keyserver,
        KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Generated server x25519 private key of: '",
        "'",
        (private_key.raw),
        (uint32_t) sizeof(private_key));

    // Construct the server's ECDHE public key and, using
    // the curve and partner (i.e., client) public key,
    // compute the shared secret
    if (0 != ecdhe_key(
            &x25519_curve,
            &partner_key,
            &private_key,
            &public_key,
            &shared_secret))
    {
        printf("Curve %s could not generate shared secret\n",
               x25519_curve.name);
        goto cleanup;
    }
    print_hex_helper(
        the_keyserver,
        !KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Generated server x25519 public key of: '",
        "'",
        (public_key.raw),
        (uint32_t) sizeof(public_key));
    print_hex_helper(
        the_keyserver,
        KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Computed x25519 shared secret of: '",
        "'",
        (shared_secret.raw),
        (uint32_t) sizeof(shared_secret));

    // Hash the shared secret into a 256-bit key to increase the
    // entropy of the key and guarantee its length.
    digest_init(sha256_digest, sha256_ctx);
    digest_update(sha256_digest, sha256_ctx, (shared_secret.raw), sizeof(shared_secret));
    digest_final(sha256_digest, sha256_ctx, sha256_out);
    print_hex_helper(
        the_keyserver,
        KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Computed AES-GCM-256 key of: '",
        "'",
        (sha256_out),
        (uint32_t) sizeof(sha256_out));

    // Copy keys into the output parameters
    memcpy(&(the_keyserver->client_pubkey), temp_decoded_key, temp_decoded_key_len);
    memcpy(&(the_keyserver->server_pubkey), (public_key.raw), sizeof((public_key.raw)));
    memcpy(&(the_keyserver->server_private_key), (private_key.raw), sizeof((private_key.raw)));
    memcpy(&(the_keyserver->shared_secret), (shared_secret.raw), sizeof((shared_secret.raw)));
    memcpy(&(the_keyserver->aes_key), sha256_out, sizeof(sha256_out));

    // Indicate success and change to the next state
    (the_keyserver->server_state) = KEYSERVER_WAITING_FOR_AUTHENTICATION;
    retval = 0;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Handles the pseudo-authentication of the client by: (1) listening
    on all ports for packets and waiting to receive the client's public key
    as a message and (2) sending the server's public x25519 key in response
    to the client's message.

    @note This is not a true "authentication" here, but rather a simple
    protocol for filtering undesired packets and allowing the server to
    quickly identify the client by receiving it's ephemeral public key
    (which it already knows). It's also worth noting there are no
    man-in-the-middle concerns here since the keyserver is only a data
    facilitator, maintains no persistent data, and sends no critical
    data (it eventually just receives and decrypts an encrypted AES-XTS-256
    key and unconditionally attempts to decrypt storage with it, which
    either works or does not work, but cannot compromise data security).
 
    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver "authentication", otherwise `-1`.
*/
int keyserver_process_state_waiting_for_authentication(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    int retval = -1;
    void * received_message = NULL;
    uint16_t received_message_len = 0;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    printf("[*] Waiting for client authentication...\n");

    // Read from socket with user-specified timeout
    if (PXENV_EXIT_SUCCESS != read_promiscuous_udp_socket_with_timeout(
            the_keyserver,
            &received_message,
            &received_message_len,
            (the_keyserver->timeout_seconds)))
    {
        printf("[x] Failed to receive UDP message...\n");
        goto cleanup;
    }

    // Authenticate the client by validating they have sent their
    // verbatim public key
    //
    // In practice, this is simply meant as a step to eliminate
    // erroneous packets (e.g., spam) from denying service to the
    // true client. Here, since the public key is ephemeral and
    // public by nature, expecting it as the first packet to be
    // provides some minor comfort. Importantly, since the server
    // never sends critical data to the client, it would not truly
    // matter, from a security perspective, if a "malign client"
    // somehow guessed the ephemeral public key and sent packets
    // to the keyserver in the small window for which it is
    // possible.
    if ((KEYSERVER_DEFAULT_ECDHE_KEY_LEN != received_message_len) ||
        (0 != memcmp(
            (the_keyserver->client_pubkey),
            received_message,
            KEYSERVER_DEFAULT_ECDHE_KEY_LEN)))
    {
        // If we could not authenticate the received packet,
        // output some debug and clear keyserver's internal
        // "UDP receive structure." By doing this, we ensure
        // only "authenticated" packets are allowed to create
        // a pseudo-connection with the server (logically
        // equivalent to a bind, in a sense)
        printf("[w] Ignoring unauthenticated packet...\n");
        memset(&(the_keyserver->pxenv_udp_read), 0, sizeof(the_keyserver->pxenv_udp_read));
    }
    // If we successfully authenticated the received packet
    // matches the expected data, proceed by sending the
    // server's public key to the client, so it can
    // compute the shared secret
    else
    {
        // Send the server's public key to the client
        if (PXENV_EXIT_SUCCESS != write_promiscuous_udp_socket(
                the_keyserver,
                (the_keyserver->server_pubkey),
                (uint16_t) sizeof(the_keyserver->server_pubkey)))
        {
            printf("[x] Failed to send UDP message...\n");
            goto cleanup;
        }

        // Indicate success and change to the next state
        printf("[*] Successfully authenticated client!\n");
        (the_keyserver->server_state) = KEYSERVER_WAITING_FOR_IV;
    }

    retval = 0;

cleanup:
    // Free resources
    if (NULL != received_message)
    {
        free(received_message);
        received_message = NULL;
    }

    return retval;
}


// ***************************************************************************
/**
    @brief Waits for the AES-GCM-256 IV to be sent by the client, sending
    an acknowledgement back to the client upon successful receipt (and 
    validation of successful IV length).

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver receipt of IV, otherwise `-1`.
*/
int keyserver_process_state_waiting_for_iv(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    int retval = -1;
    void * received_message = NULL;
    uint16_t received_message_len = 0;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    printf("[*] Waiting for client to send IV...\n");

    // Read from socket with user-specified timeout
    if (PXENV_EXIT_SUCCESS != read_promiscuous_udp_socket_with_timeout(
            the_keyserver,
            &received_message,
            &received_message_len,
            (the_keyserver->timeout_seconds)))
    {
        printf("[x] Failed to receive UDP message...\n");
        goto cleanup;
    }
    print_hex_helper(
        the_keyserver,
        !KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Received IV of: '",
        "'",
        received_message,
        (uint32_t) received_message_len);

    // The client will generate and send a random IV to the server,
    // so, validate it is of the appropriate length here
    if (KEYSERVER_DEFAULT_AES_GCM_IV_LEN != received_message_len)
    {
        printf("[x] Failed to receive IV...\n");
        goto cleanup;
    }

    // Send the server's public key to the client as an ack
    //
    // This could be made into a more relevant message, but
    // using the public key is a reasonable way to mitigate
    // spam, since it's an ephemeral, but known message
    if (PXENV_EXIT_SUCCESS != write_promiscuous_udp_socket(
            the_keyserver,
            (the_keyserver->server_pubkey),
            (uint16_t) sizeof(the_keyserver->server_pubkey)))
    {
        printf("[x] Failed to send UDP message...\n");
        goto cleanup;
    }

    // Indicate success and change to the next state
    printf("[*] Successfully received IV from client!\n");
    memcpy(&(the_keyserver->aes_iv), received_message, (size_t) received_message_len);
    (the_keyserver->server_state) = KEYSERVER_WAITING_FOR_DISK_KEY;
    retval = 0;

cleanup:
    // Free resources
    if (NULL != received_message)
    {
        free(received_message);
        received_message = NULL;
    }

    return retval;
}


// ***************************************************************************
/**
    @brief Waits for the encrypted AES-XTS-256 key to be sent by the client,
    subsequently sending an acknowledgement of receipt to the client.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver receipt of encrypted AES-XTS-256 key,
    otherwise `-1`.
*/
int keyserver_process_state_waiting_for_disk_key(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    int retval = -1;
    void * received_message = NULL;
    uint16_t received_message_len = 0;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    printf("[*] Waiting for client to send encrypted AES-XTS-256 key...\n");

    // Read from socket with user-specified timeout
    if (PXENV_EXIT_SUCCESS != read_promiscuous_udp_socket_with_timeout(
            the_keyserver,
            &received_message,
            &received_message_len,
            (the_keyserver->timeout_seconds)))
    {
        printf("[x] Failed to receive UDP message...\n");
        goto cleanup;
    }
    print_hex_helper(
        the_keyserver,
        KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Received encrypted AES-XTS-256 key of: '",
        "'",
        received_message,
        (uint32_t) received_message_len);

    // Send the server's public key to the client as an ack
    //
    // This could be made into a more relevant message, but
    // using the public key is a reasonable way to mitigate
    // spam, since it's an ephemeral, but known message
    if (PXENV_EXIT_SUCCESS != write_promiscuous_udp_socket(
            the_keyserver,
            (the_keyserver->server_pubkey),
            (uint16_t) sizeof(the_keyserver->server_pubkey)))
    {
        printf("[x] Failed to send UDP message...\n");
        goto cleanup;
    }

    // Indicate success and change to the next state
    printf("[*] Successfully received AES-XTS-256 key from client!\n");
    memcpy(
        &(the_keyserver->encrypted_aes_xts_256_disk_key),
        received_message,
        (size_t) received_message_len);
    (the_keyserver->encrypted_aes_xts_256_disk_key_len) = received_message_len;
    (the_keyserver->server_state) = KEYSERVER_DECRYPTING_DISK_KEY;
    retval = 0;

cleanup:
    // Free resources
    if (NULL != received_message)
    {
        free(received_message);
        received_message = NULL;
    }

    return retval;
}


// ***************************************************************************
/**
    @brief Uses the already-computed (via x25519 ECDHE) ephemeral AES-GCM-256 key
    and IV to decrypt the previously-received, encrypted AES-XTS-256 key.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver decryption of encrypted AES-XTS-256 key,
    otherwise `-1`.
*/ 
int keyserver_process_state_decrypting_disk_key(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    void * aes_gcm_ctx = NULL;
    int retval = -1;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    printf("[*] Decrypting encrypted AES-XTS-256 key...\n");

    // Allocate memory for our context
    aes_gcm_ctx = zalloc(sizeof(struct gcm_context) + AES_CTX_SIZE);
    if (NULL == aes_gcm_ctx)
    {
        printf("[x] Failed to allocate '%d' bytes for 'aes_gcm_ctx'\n",
            (int) sizeof(struct gcm_context));
        goto cleanup;
    }

    // Set the key for our AES GCM context
    if (0 != cipher_setkey(
        &aes_gcm_algorithm,
        aes_gcm_ctx,
        (the_keyserver->aes_key),
        KEYSERVER_DEFAULT_AES_GCM_256_KEY_LEN))
    {
        printf("[x] Failed to set AES key!\n");
        goto cleanup;
    }

    // Set the IV for our AES GCM context
    cipher_setiv(
        &aes_gcm_algorithm,
        aes_gcm_ctx,
        (the_keyserver->aes_iv),
        KEYSERVER_DEFAULT_AES_GCM_IV_LEN);

    // Decrypt the encrypted key
    cipher_decrypt(
        &aes_gcm_algorithm,
        aes_gcm_ctx,
        (the_keyserver->encrypted_aes_xts_256_disk_key),
        (the_keyserver->aes_xts_256_disk_key),
        (the_keyserver->encrypted_aes_xts_256_disk_key_len));
    
    // Update the new disk key length to remove the GCM prefix
    (the_keyserver->encrypted_aes_xts_256_disk_key_len) -= KEYSERVER_DEFAULT_AES_GCM_PREFIX_LEN;

    // Debug print
    print_hex_helper(
        the_keyserver,
        KEYSERVER_DEBUG_PRINT_ONLY,
        "[*] Successfully decrypted encrypted AES-XTS-256 key into: '",
        "'",
        (the_keyserver->aes_xts_256_disk_key),
        (uint32_t) (the_keyserver->encrypted_aes_xts_256_disk_key_len));

    // Indicate success and change to the next state
    printf("[*] Successfully decrypted encrypted AES-XTS-256 key from client!\n");
    (the_keyserver->server_state) = KEYSERVER_BOOT;
    retval = 0;

cleanup:
    // Free resources
    if (NULL != aes_gcm_ctx)
    {
        free(aes_gcm_ctx);
        aes_gcm_ctx = NULL;
    }

    return retval;
}

// ***************************************************************************
/**
    @brief Uses the supplied boot images (kernel and initrd) along with the
    decrypted key (or passphrase) to boot the underlying guest system.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns On success, this function exits the bootloader and boots the specified
    kernel and initrd, otherwise, returns -1.
*/ 
int keyserver_process_state_boot(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    char * argv_image[128];
    char * argv_kernel[128];
    char * argv_boot[2];
    char passphrase_buffer[4096];
    int argc_image = sizeof(argv_image) / sizeof(*argv_image);
    int argc_kernel = (sizeof(argv_kernel) / sizeof(*argv_kernel)) - 1;
    int argc_boot = 1;
    int retval = -1;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }

    // Set relevant data, noting
    // "boot" is always the same command structure
    memset(argv_image, 0, sizeof(argv_image));
    memset(argv_kernel, 0, sizeof(argv_kernel));
    memset(argv_boot, 0, sizeof(argv_boot));
    memset(passphrase_buffer, 0, sizeof(passphrase_buffer));
    memcpy(passphrase_buffer, KEYSERVER_PASSPHRASE_PREFIX, KEYSERVER_PASSPHRASE_PREFIX_LEN);
    argv_boot[0] = "boot";

    // If image and kernel parameters were both provided, boot the image
    if ((NULL != (the_keyserver->initrd_command_line)) &&
        (NULL != (the_keyserver->kernel_command_line)))
    {
        printf("[*] Booting with image command '%s' and "   
               "kernel command line '%s'...\n",
            (the_keyserver->initrd_command_line),
            (the_keyserver->kernel_command_line));
        
        // Get image and kernels params 
        if (0 != string_to_argv_argc(
                the_keyserver->initrd_command_line,
                &argc_image,
                (char **) &argv_image))
        {
            printf("[x] Failed to extract image command line...\n");
            goto cleanup;
        }
        if (0 != string_to_argv_argc(
                the_keyserver->kernel_command_line,
                &argc_kernel,
                (char **) &argv_kernel))
        {
            printf("[x] Failed to extract kernel command line...\n");
            goto cleanup;
        }

        // Add in the key/passphrase to the kernel output
        memcpy(&(passphrase_buffer[KEYSERVER_PASSPHRASE_PREFIX_LEN]),
            (the_keyserver->aes_xts_256_disk_key),
            (the_keyserver->encrypted_aes_xts_256_disk_key_len));
        argv_kernel[argc_kernel] = passphrase_buffer;   
        argc_kernel++;
        
        // Fetch images based on supplied URIs and command line
        // parameters
        if (0 != imgfetch_exec(argc_image, argv_image))
        {
            printf("[x] Failed to fetch initrd image "
                "from command line '%s'\n",
                the_keyserver->initrd_command_line);
            goto cleanup;
        }
        if (0 != imgselect_exec(argc_kernel - 1, argv_kernel))
        {
            printf("[x] Failed to fetch kernel image "
                "from command line '%s'\n",
                the_keyserver->kernel_command_line);
            goto cleanup;
        }     

        printf("[*] Booting images...\n");
        if (0 != imgexec_exec(argc_boot, argv_boot))
        {
            printf("[x] Boot failed...\n");
            goto cleanup;
        }
        // Should never reach here on success, as the bootloader
        // will chainboot the underlying system
    }
    // Otherwise, no boot was requested

    (the_keyserver->server_state) = KEYSERVER_COMPLETE;
    retval = 0;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Gets and prints the ip string of the keyserver.

    @warning    It is the responsibility of the caller to free memory
                pointed to by (*the_ip_string) on successful function
                execution (i.e., when `0` is returned).

    @param[out]  the_ip_string 
                    On success, this outout parameter will point to a
                    null-terminted string containing the IPv4 address of
                    the keyserver (otherwise, its value is unspecified).

    @returns 0 on successful keyserver decryption of encrypted AES-XTS-256 key,
    otherwise `-1`.
*/ 
int get_and_print_ip(
    char ** the_ip_string)
{
    // Initialize variables
    int len = -1;
    char * value = NULL;
    struct named_setting setting = {0};
    struct settings * origin = NULL;
    struct setting fetched = {0};
    int rc = -1;

    // Check input parameters
    if (NULL == the_ip_string)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_ip_string' was '%p'\n",
            the_ip_string);
        goto cleanup;
    }
    (*the_ip_string) = NULL;

    // Parse setting name
    if (0 != (rc = parse_existing_setting ("ip", &setting)))
    {
        printf("[x] Failed to get current ip settings...\n");
        goto cleanup;
    }

    // Fetch formatted setting value
    if (0 > (len = fetchf_setting_copy(
                        setting.settings,
                        &setting.setting,
                        &origin,
                        &fetched,
                        &value)))
    {
        rc = len;
        printf("[x] Could not find \"%s\": %s\n",
             setting.setting.name, strerror (rc));
        goto cleanup;
    }

    // Print setting value and copy the memory
    // address to our output param
    printf("[*] Server IP address: '%s'\n", value);
    (*the_ip_string) = value;
    rc = 0;

cleanup:
    return rc;
}


// ***************************************************************************
/**
    @brief Opens a promiscuous UDP socket.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns `PXENV_EXIT_SUCCESS` on successful promiscuous UDP socket opening,
    otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t open_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    PXENV_EXIT_t px_rc = PXENV_EXIT_FAILURE;
    PXENV_EXIT_t retval = PXENV_EXIT_FAILURE;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }
    (the_keyserver->socket_state) = KEYSERVER_SOCKET_CLOSED;

    // Populate relevant structures
    //
    // Using a src_ip of 0 leaves the local IP
    // address unchanged
    ((the_keyserver->pxenv_udp_open).src_ip) = 0;
    ((the_keyserver->pxenv_udp_open).Status) = PXENV_STATUS_FAILURE;

    // Open a UDP socket
    px_rc = PXE_UDP_OPEN((union u_PXENV_ANY *) &(the_keyserver->pxenv_udp_open));
    if (PXENV_EXIT_SUCCESS != px_rc)
    {
        printf("[x] Failed to open UDP socket...\n");
        goto cleanup;
    }
    printf("[*] Successfully opened UDP socket!\n");

    // Initialize relevant keyserver fields
    memset(&(the_keyserver->pxenv_udp_read), 0, sizeof(the_keyserver->pxenv_udp_read));
    memset(&(the_keyserver->pxenv_udp_write), 0, sizeof(the_keyserver->pxenv_udp_write));
    (the_keyserver->socket_state) = KEYSERVER_SOCKET_OPEN;

    // Indicate success
    retval = PXENV_EXIT_SUCCESS;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Closes a promiscuous UDP socket.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns `PXENV_EXIT_SUCCESS` on successful closure of UDP socket,
    otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t close_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver)
{
    // Initialize variables
    PXENV_EXIT_t retval = PXENV_EXIT_FAILURE;
    PXENV_EXIT_t px_rc = PXENV_EXIT_FAILURE;

    // Check input parameters
    if (NULL == the_keyserver)
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n",
            the_keyserver);
        goto cleanup;
    }

    // If the socket is not open, there is no need to close it
    if (KEYSERVER_SOCKET_CLOSED != (the_keyserver->socket_state))
    {
        // Close the udp socket
        px_rc = PXE_UDP_CLOSE((union u_PXENV_ANY *) &(the_keyserver->pxenv_udp_close));
        if (PXENV_EXIT_SUCCESS != px_rc)
        {
            printf("[x] Failed to close UDP socket...\n");
            goto cleanup;
        }
        printf("[*] Successfully closed UDP socket!\n");
    }
    // Otherwise, the socket was already closed
    else
    {
        printf("[w] UDP socket not open. Skipping closure..\n");
    }

    // Reset relevant keyserver fields
    memset(&(the_keyserver->pxenv_udp_read), 0, sizeof(the_keyserver->pxenv_udp_read));
    memset(&(the_keyserver->pxenv_udp_write), 0, sizeof(the_keyserver->pxenv_udp_write));
    (the_keyserver->socket_state) = KEYSERVER_SOCKET_CLOSED;

    // Indicate success
    retval = PXENV_EXIT_SUCCESS;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Reads a UDP packet (up to `KEYSERVER_UDP_BUFFER_SIZE` bytes)
    from the logical socket.

    @warning    It is the responsibility of the caller to free memory
                pointed to by (*the_buffer_out) on successful function
                execution (i.e., when `PXENV_EXIT_SUCCESS` is returned).

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @param[out] the_buffer_out 
                    On success, an output parameter pointing to
                    a newly allocated buffer containing
                    `(*the_buffer_out_len)` bytes received via UDP
                    (otherwise, its value is unspecified).                    

    @param[out] the_buffer_out_len 
                    An output parameter which will point to the number
                    of bytes indexable via (*the_buffer_out) on success
                    (otherwise, its value is unspecified).

    @returns `PXENV_EXIT_SUCCESS` on successful packet read from
    UDP socket, otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t read_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver,
    void ** the_buffer_out,
    uint16_t * the_buffer_out_len)
{
    // Initialize variables
    PXENV_EXIT_t retval = PXENV_EXIT_FAILURE;
    PXENV_EXIT_t px_rc = PXENV_EXIT_FAILURE;

    // Since MTU is typically far less than 4096 bytes,
    // (and since this buffer size is certainly large
    // enough for our application), use a stack allocate
    // buffer with a fixed size to receive UDP packets
    uint8_t udp_buffer[KEYSERVER_UDP_BUFFER_SIZE + 1];

    // Check input parameters
    if ((NULL == the_keyserver) ||
        (NULL == the_buffer_out) ||
        (NULL == the_buffer_out_len))
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n"
                   "\t'the_buffer_out' was '%p'\n"
                   "\t'the_buffer_out_len' was '%p'\n",
            (void *) the_keyserver,
            (void *) the_buffer_out,
            (void *) the_buffer_out_len);
        goto cleanup;
    }
    (*the_buffer_out) = NULL;
    (*the_buffer_out_len) = 0;
    memset(udp_buffer, 0, sizeof(udp_buffer));

    // If the socket is not open, we cannot read from it
    if (KEYSERVER_SOCKET_OPEN != (the_keyserver->socket_state))
    {
        printf("[x] UDP socket not open. Skipping read..\n");
        goto cleanup;
    }
    // Otherwise, the socket is open

    // When reading, use the existing source/dest information which,
    // by default, is 0 (accept all packets) and is otherwise set
    // to match a specific, authenticated sender.
    ((the_keyserver->pxenv_udp_read).buffer) = udp_buffer;
    ((the_keyserver->pxenv_udp_read).buffer_size) = (uint16_t) KEYSERVER_UDP_BUFFER_SIZE;

    // Read from the udp socket
    px_rc = PXE_UDP_READ((union u_PXENV_ANY *) &(the_keyserver->pxenv_udp_read));

    // If the function failed, consider it a legitimate error and print some
    // debug
    if (PXENV_EXIT_SUCCESS != px_rc)
    {
        printf("[x] Failed to read from UDP socket...\n");
        goto cleanup;
    }
    // Otherwise, if no message was found, do not print any debug
    // (since this function may be looped and it would otherwise
    // spam the console), but simply jump to cleanup
    else if (PXENV_STATUS_SUCCESS != ((the_keyserver->pxenv_udp_read).Status))
    {
        goto cleanup;
    }
    // Otherwise, the read was successful

    // Only print "success-related" output if verbose logging
    // is specified
    if (0 != (KEYSERVER_VERBOSE & (the_keyserver->options)))
    {
        printf("[*] %s:%d <- %s:%d | Received '%d' bytes\n",
            (the_keyserver->ip_string),
            htons((the_keyserver->pxenv_udp_read).d_port),
            inet_ntoa(*((struct in_addr *) &((the_keyserver->pxenv_udp_read).src_ip))),
            htons((the_keyserver->pxenv_udp_read).s_port),
            (int) (the_keyserver->pxenv_udp_read).buffer_size);
    }

    // Copy the buffer and its respective size into our output buffer
    (*the_buffer_out) = zalloc(((the_keyserver->pxenv_udp_read).buffer_size) + 1);
    if (NULL == (*the_buffer_out))
    {
        printf("[x] Failed to copy output buffer of '%d' bytes, "
               "could not allocate memory\n",
               (int) (((the_keyserver->pxenv_udp_read).buffer_size) + 1));
        goto cleanup;
    }
    memcpy(
        (*the_buffer_out),
        ((the_keyserver->pxenv_udp_read).buffer),
        ((the_keyserver->pxenv_udp_read).buffer_size));
    (*the_buffer_out_len) = (uint16_t) ((the_keyserver->pxenv_udp_read).buffer_size);
    ((uint8_t *) (*the_buffer_out))[(*the_buffer_out_len)] = 0;

    // Indicate success
    retval = PXENV_EXIT_SUCCESS;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief Waits up to `the_seconds_timeout` seconds to receive a UDP packet
    (up to `KEYSERVER_UDP_BUFFER_SIZE` bytes) from the logical socket before
    giving up.

    @warning    It is the responsibility of the caller to free memory
                pointed to by (*the_buffer_out) on successful function
                execution (i.e., when `PXENV_EXIT_SUCCESS` is returned).

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @param[out] the_buffer_out 
                    On success, an output parameter pointing to
                    a newly allocated buffer containing
                    `(*the_buffer_out_len)` bytes received via UDP
                    (otherwise, its value is unspecified).                    

    @param[out] the_buffer_out_len 
                    An output parameter which will point to the number
                    of bytes indexable via (*the_buffer_out) on success
                    (otherwise, its value is unspecified).                 

    @param[in] the_seconds_timeout 
                    The number of seconds to wait before giving up
                    and abandoning the read attempt (reporting failure
                    in such a case).

    @returns `PXENV_EXIT_SUCCESS` on successful packet read from
    UDP socket within `the_seconds_timeout` seconds, otherwise,
    `PXENV_EXIT_FAILURE`.
*/ 
int read_promiscuous_udp_socket_with_timeout(
    keyserver_info_t * the_keyserver,
    void ** the_buffer_out,
    uint16_t * the_buffer_out_len,
    uint32_t the_seconds_timeout)
{
    // Initialize variables
    PXENV_EXIT_t px_rc = PXENV_EXIT_FAILURE;
    uint64_t remaining_time_seconds = (uint64_t) the_seconds_timeout;
    int retval = -1;

    // Check input parameters
    if ((NULL == the_keyserver) ||
        (NULL == the_buffer_out) ||
        (NULL == the_buffer_out_len))
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n"
                   "\t'the_buffer_out' was '%p'\n"
                   "\t'the_buffer_out_len' was '%p'\n",
            (void *) the_keyserver,
            (void *) the_buffer_out,
            (void *) the_buffer_out_len);
        goto cleanup;
    }

    // Only print timeout information if verbose logging
    // is specified
    if (0 != (KEYSERVER_VERBOSE & (the_keyserver->options)))
    {
        printf("[*] Reading from promiscuous UDP socket with "
               "a timeout of '%d' seconds\n",
               the_seconds_timeout);
    }

    // This function does not support an explicitly blocking read,
    // since an extremely large amount of time can easily be specified
    // as the timeout, which, in effect, can be considered reasonably
    // equivalent to blocking
    while (0 < remaining_time_seconds)
    {
        // Try reading from the socket; if successful,
        // we can break the loop
        px_rc = read_promiscuous_udp_socket(
            the_keyserver,
            the_buffer_out,
            the_buffer_out_len);
        if (PXENV_EXIT_SUCCESS == px_rc)
        {
            // Indicate success and terminate
            // early
            retval = 0;
            break;
        }
        // Otherwise, sleep, decrement the remaining time,
        // and try again
        sleep(KEYSERVER_SLEEP_INTERVAL_SECONDS);

        // If we slept for more time than was actually remaining,
        // simply set the time to 0, otherwise decrement the
        // remaining time by the time slept
        remaining_time_seconds = (remaining_time_seconds < KEYSERVER_SLEEP_INTERVAL_SECONDS) ?
            0 : (remaining_time_seconds - KEYSERVER_SLEEP_INTERVAL_SECONDS);
    }

cleanup:
    // If no packet was found, output some debug
    if (0 != retval)
    {
        printf("[*] No packet received within '%d' seconds, "
               "done receiving.\n",
               (int) the_seconds_timeout);
    }

    return retval;
}


// ***************************************************************************
/**
    @brief Sends a UDP packet via the logical socket to the already established
    (via the first successful read) endpoint.

    @warning    This function can only succeed if a message has already been
                received from the desired endpoint (since this is how the
                destination IP and port become known to the keyserver).

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @param[in]  the_buffer
                    The buffer to send via the logical UDP socket.                    

    @param[in]  the_bufferlen 
                    The number of bytes indexable via `the_buffer`.

    @returns `PXENV_EXIT_SUCCESS` on successful packet write to UDP
    socket, otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t write_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver,
    const void * the_buffer,
    uint16_t the_buffer_len)
{
    // Initialize variables
    PXENV_EXIT_t retval = PXENV_EXIT_FAILURE;
    PXENV_EXIT_t px_rc = PXENV_EXIT_FAILURE;

    // Check input parameters
    if ((NULL == the_keyserver) ||
        (NULL == the_buffer))
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n"
                   "\t'the_buffer' was '%p'\n",
            (void *) the_keyserver,
            (void *) the_buffer);
        goto cleanup;
    }

    // If the socket is not open, we cannot write to it
    if (KEYSERVER_SOCKET_OPEN != (the_keyserver->socket_state))
    {
        printf("[x] UDP socket not open. Skipping write..\n");
        goto cleanup;
    }
    // Otherwise, the socket is open

    // We need to have performed a "read" operation and received relevant
    // src_ip and src_port information from the client before we can
    // response (i.e., before we can perform a "UDP write"); thus, check
    // here if we have non-zero values for "src_ip" and "s_port"
    // within the read context. If we do, we can continue; otherwise,
    // we cannot.
    if ((0 == ((the_keyserver->pxenv_udp_read).src_ip)) ||
        (0 == ((the_keyserver->pxenv_udp_read).s_port)))
    {
        printf("[x] We have not yet received an initialization message "
               "from a client server. Refusing to send UDP packets...\n");
        goto cleanup;
    }
    // Otherwise, we have another information to send a packet, so
    // populate the pxenv udp write fields, as appropriate, where
    // the "source fields" of the read structure become the destination
    // fields of the write structure (i.e., we response to the
    // sender, and no-one else).

    // Set the "relay" ip address (the dest of the read
    // address is sufficient to use for this; basically
    // it's just the "bind" address, more or less)
    (the_keyserver->pxenv_udp_write).gw = (the_keyserver->pxenv_udp_read).dest_ip;

    // Destination IP (the source of the read address is
    // equivalent to the destination of the write address)
    (the_keyserver->pxenv_udp_write).ip = (the_keyserver->pxenv_udp_read).src_ip;

    // The destination port from the reader is used as the source
    // port of the sender (us), and vice versa
    (the_keyserver->pxenv_udp_write).src_port = (the_keyserver->pxenv_udp_read).d_port;
    (the_keyserver->pxenv_udp_write).dst_port = (the_keyserver->pxenv_udp_read).s_port;

    // Pass the buffers, verbatim
    (the_keyserver->pxenv_udp_write).buffer_size = the_buffer_len;
    (the_keyserver->pxenv_udp_write).buffer = (void *) the_buffer;

    // Only print transit information if verbose logging
    // is specified
    if (0 != (KEYSERVER_VERBOSE & (the_keyserver->options)))
    {
        printf("[*] %s:%d -> %s:%d | Sending '%d' bytes\n",
                (the_keyserver->ip_string),
                htons((the_keyserver->pxenv_udp_write).src_port),
                inet_ntoa(*((struct in_addr *) &((the_keyserver->pxenv_udp_write).ip))),
                htons((the_keyserver->pxenv_udp_write).dst_port),
                the_buffer_len);
    }

    // Write to the udp socket
    px_rc = PXE_UDP_WRITE((union u_PXENV_ANY *) &(the_keyserver->pxenv_udp_write));
    if ((PXENV_EXIT_SUCCESS != px_rc) ||
        (PXENV_STATUS_SUCCESS != ((the_keyserver->pxenv_udp_write).Status)))
    {
        printf("[x] Failed to write to UDP socket...\n");
        goto cleanup;
    }

    // Indicate success
    retval = PXENV_EXIT_SUCCESS;

cleanup:
    return retval;
}


// ***************************************************************************
/**
    @brief A helper function used to print a supplied buffer as a hex string.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @param[in]  the_debug_only
                    An integer used to identify whether to skip prints
                    if `-d` was not supplied to the keyserver at 
                    launch time (0 == do not skip, while any other value 
                    indicates a skip request).

    @param[in]  the_prefix_string
                    An optional string to print prior to the hex data
                    (NULL may be supplied to skip adding a prefix).   

    @param[in]  the_suffix_string
                    An optional string to print after to the hex data
                    (NULL may be supplied to skip adding a suffix).  

    @param[in]  the_data
                    The buffer to print.                   

    @param[in]  the_data_len 
                    The number of bytes indexable via `the_data`.
*/ 
void print_hex_helper(
    keyserver_info_t * the_keyserver,
    uint8_t the_debug_only,
    const char * the_prefix_string,
    const char * the_suffix_string,
    const uint8_t * the_data,
    uint32_t the_data_len)

{
    // Check input parameters
    if ((NULL == the_keyserver) ||
        (NULL == the_data) ||
        (0 == the_data_len))
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_keyserver' was '%p'\n"
                   "\t'the_data' was '%p'\n"
                   "\t'the_data_len' was '%llu'\n",
            (void *) the_keyserver,
            (void *) the_data,
            (long long unsigned) the_data_len);
        goto cleanup;
    }

    // If "debug only" printing was requested, but debug mode
    // is not active, refuse to print
    if ((0 != the_debug_only) &&
        (0 == (KEYSERVER_DEBUG & (the_keyserver->options))))
    {
        goto cleanup;
    }
    // Otherwise, perform hex prints if verbose printing was
    // requested
    else if (0 != (KEYSERVER_VERBOSE & (the_keyserver->options)))
    {
        // If a prefix string was specified, print it first
        if (NULL != the_prefix_string)
        {
            printf("%s", the_prefix_string);
        }

        // Now, print the raw data
        for (uint32_t i = 0; i < the_data_len; i++)
        {
            printf("%02x", the_data[i]);
        }

        // If a suffix string was specified, print it first
        if (NULL != the_suffix_string)
        {
            printf("%s", the_suffix_string);
        }

        // Always terminate with a newline
        printf("\n");
    }
    // Otherwise, there is nothing to print

cleanup:
    return;
}


// ***************************************************************************
/**
    @brief Turn a string into an argv/argc representation by simply
    overwriting pipes with null terminators. 

    @warning This function assumes verbatim strings are passed in and does
    absolutely no "interpreter equivalent" escaping.

    @warning The input string will be be manipulated (pipes will be
    turned into null terminators), so the caller may wish to make a copy.

    @param[in] the_string
                The string to turn into argc/argv

    @param[in,out] the_argc_out
                As an input parameter, the number of elements in `the_argv_out`
                available to use. As an output parameter, the number of 
                elements used (or unspecified on function failure).

    @param[out] the_argv_out
                The "argv style" list of pointers extract from `the_string`.

    @returns `0` on success, otherwise `-1`
*/
int string_to_argv_argc(
    char * the_string,
    int * the_argc_out,
    char ** the_argv_out)
{
    int arguments = 0;
    int offset = 0;
    int space = 0;
    int retval = -1;

    // Check input parameters
    if ((NULL == the_string) ||
        (NULL == the_argc_out) ||
        (NULL == the_argv_out))
    {
        printf("[x] Received invalid parameters:\n"
                   "\t'the_string' was '%p'\n"
                   "\t'the_argc_out' was '%p'\n"
                   "\t'the_argv_out' was '%p'\n",
            (void *) the_string,
            (void *) the_argc_out,
            (void *) the_argv_out);
        goto cleanup;
    }
    space = (*the_argc_out);

    // Count the number of arguments needed, based on the number of pipes
    // and assuming any otherwise non-null character is part of an argument
    while ('\0' != the_string[offset])
    {
        // Count arguments and skip pipes 
        // (also count the null terminator as an argument
        // delimiter, but only once)
        if (('|' == the_string[offset]) ||
            ('\0' != the_string[offset]))
        {
            // Skip any remaining pipes
            while ('|' == the_string[offset])
            {
                offset++;
            }
            arguments++;
        }

        offset++;
    }

    // Check to ensure there is enough space available
    // (note the final space is reserve for null, so 
    // they cannot even be equal)
    if (arguments >= space)
    {
        printf("[x] Supplied room for '%d' arguments but have '%d'. Skipping...\n",
            space, arguments);
        goto cleanup;
    }

    // Ensure we have at least one non-null argument
    if (0 == arguments)
    {
        printf("[x] '%s' contains no arguments. Skipping...\n",
            the_string);
        goto cleanup;
    }

    // Extract the arguments using simple pointer magic (also overwriting
    // pipes with null terminators)
    offset = 0;
    arguments = 0;
    while ('\0' != the_string[offset])
    {
        the_argv_out[arguments] = &(the_string[offset]);

        // Skip to pipes or null terminators
        while (('|' != the_string[offset]) &&
               ('\0' != the_string[offset]))
        {
            offset++;
        }
        
        // Overwrite all pipes with null terminators
        while ('|' == the_string[offset])
        {
            the_string[offset] = '\0';
            offset++;
        }

        // Prepare for next argument
        arguments++;
    }
    // Set the last argument pointer to null, as is convention
    the_argv_out[arguments] = NULL;

    // Indicate success
    (*the_argc_out) = arguments;
    retval = 0;

cleanup:
    return retval;
}
