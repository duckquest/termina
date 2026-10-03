#ifndef _IPXE_KEYSERVER_H
#define _IPXE_KEYSERVER_H

/** @file
 *
 * iPXE keyserver API
 *
 */

FILE_LICENCE ( GPL2_OR_LATER_OR_UBDL );
FILE_SECBOOT ( PERMITTED );

#include <stdint.h>

#include <config/keyserver.h>

#include <ipxe/api.h>

#include <pxe.h>
#include <pxe_api.h>


// ***************************************************************************
/**
 * Calculate static inline keyserver API function name
 *
 * @v _prefix           Subsystem prefix
 * @v _api_func         API function
 * @ret _subsys_func    Subsystem API function
 */
#define KEYSERVER_INLINE( _subsys, _api_func ) \
    SINGLE_API_INLINE ( KEYSERVER_PREFIX_ ## _subsys, _api_func )


/**
 * Provide an keyserver API implementation
 *
 * @v _prefix           Subsystem prefix
 * @v _api_func         API function
 * @v _func             Implementing function
 */
#define PROVIDE_KEYSERVER( _subsys, _api_func, _func ) \
    PROVIDE_SINGLE_API ( KEYSERVER_PREFIX_ ## _subsys, _api_func, _func )


/**
 * Provide a static inline keyserver API implementation
 *
 * @v _prefix           Subsystem prefix
 * @v _api_func         API function
 */
#define PROVIDE_KEYSERVER_INLINE( _subsys, _api_func ) \
    PROVIDE_SINGLE_API_INLINE ( KEYSERVER_PREFIX_ ## _subsys, _api_func )


// Use verbose logging
#define KEYSERVER_VERBOSE                               (1 << 0)


// Use debug logging
#define KEYSERVER_DEBUG                                 (1 << 1)


// Default UDP buffer size
#define KEYSERVER_UDP_BUFFER_SIZE                       (4096)


// The number of seconds to sleep between successive
// read calls when performing reads with timeout
// (i.e., within `read_promiscuous_udp_socket_with_timeout(...))
#define KEYSERVER_SLEEP_INTERVAL_SECONDS                ((uint64_t) 1)


// The default key size for ECHDE when generating a 256-bit shared
// secret (to later be hashed, via sha-256, into a 256-bit
// AES-GCM-256 key)
#define KEYSERVER_DEFAULT_ECDHE_KEY_LEN                 (32)


// The length, in bytes, of the AES GCM 256 algorithm's
// key (i.e., 32 bytes)
#define KEYSERVER_DEFAULT_AES_GCM_256_KEY_LEN           (32)


// The NIST recommended IV length for AES GCM 256, in bytes
#define KEYSERVER_DEFAULT_AES_GCM_IV_LEN                (12)


// The length, in bytes, of the AES GCM 256 algorithms prefix
// (used for integrity of data)
#define KEYSERVER_DEFAULT_AES_GCM_PREFIX_LEN            (16)


// The length, in bytes, of the AES XTS 256 algorithm's
// key (i.e., 32 bytes)
#define KEYSERVER_DEFAULT_AES_XTS_256_KEY_LEN           (32)


// A helper constant used to identify print messages
// only meant to be print when the `KEYSERVER_DEBUG`
// option was specified
#define KEYSERVER_DEBUG_PRINT_ONLY                      (1)


// Helper macros
#define PXE_UDP_OPEN                                    (((pxe_udp_api[0]).entry))
#define PXE_UDP_CLOSE                                   (((pxe_udp_api[1]).entry))
#define PXE_UDP_READ                                    (((pxe_udp_api[3]).entry))
#define PXE_UDP_WRITE                                   (((pxe_udp_api[2]).entry))


// The default passphrase prefix and length
#define KEYSERVER_PASSPHRASE_PREFIX                     "passphrase="
#define KEYSERVER_PASSPHRASE_PREFIX_LEN                 (strlen(KEYSERVER_PASSPHRASE_PREFIX))


// ***************************************************************************
// An external reference to the PXU UDP api function calls
extern struct pxe_api_call pxe_udp_api[];


// An external reference to the elliptic curve structure specifically
// initialized for the standardized x25519 curve
extern struct elliptic_curve x25519_curve;


// Extern references for boot helpers
extern int imgfetch_exec(int argc, char ** argv);
extern int imgselect_exec(int argc, char ** argv);
extern int imgexec_exec(int argc, char ** argv);

// ***************************************************************************
// Typedef enum for representing socket state
typedef enum keyserver_socket_state_e
{
    // It is important to have 'closed'
    // be equal to `0`, so it begins in the
    // closed state when initialized to 0
    KEYSERVER_SOCKET_CLOSED = 0,
    KEYSERVER_SOCKET_OPEN = 1
} keyserver_socket_state_t;


// Typedef enum for representing server state
typedef enum keyserver_server_state_e
{
    // It is important to have 'init'
    // be equal to `0`, so it begins in the
    // init state when initialized to 0
    KEYSERVER_INIT = 0,
    KEYSERVER_WAITING_FOR_AUTHENTICATION,
    KEYSERVER_WAITING_FOR_IV,
    KEYSERVER_WAITING_FOR_DISK_KEY,
    KEYSERVER_DECRYPTING_DISK_KEY,
    KEYSERVER_BOOT,
    KEYSERVER_COMPLETE
} keyserver_server_state_t;


// Typedef structure to hold relevant keyserver data
typedef struct keyserver_info_s
{
    // UDP socket management structures
    struct s_PXENV_UDP_OPEN         pxenv_udp_open;
    struct s_PXENV_UDP_CLOSE        pxenv_udp_close;
    struct s_PXENV_UDP_READ         pxenv_udp_read;
    struct s_PXENV_UDP_WRITE        pxenv_udp_write;

    // The state of the socket
    keyserver_socket_state_t        socket_state;

    // The state of the server
    keyserver_server_state_t        server_state;

    // Keyserver options
    int                             options;
    int32_t                         timeout_seconds;

    // IP information
    const char *                    ip_string;

    // =============================
    // x25519 ECDHE Information
    // =============================
    // The ephemeral b64_client_pubkey bytes
    uint8_t *                       b64_client_pubkey;

    // The length of the b64_client_pubkey, in bytes
    uint32_t                        b64_client_pubkey_len;

    // The ephemeral client_pubkey bytes
    uint8_t                         client_pubkey[KEYSERVER_DEFAULT_ECDHE_KEY_LEN];

    // The ephemeral server_pubkey bytes
    uint8_t                         server_pubkey[KEYSERVER_DEFAULT_ECDHE_KEY_LEN];

    // The ephemeral server_private_key
    uint8_t                         server_private_key[KEYSERVER_DEFAULT_ECDHE_KEY_LEN];

    // The ephemeral shared_secret
    uint8_t                         shared_secret[KEYSERVER_DEFAULT_ECDHE_KEY_LEN];

    // =============================
    // AES-GCM 256 information
    // =============================
    // The aes key
    uint8_t                         aes_key[KEYSERVER_DEFAULT_AES_GCM_256_KEY_LEN];

    // The aes IV
    uint8_t                         aes_iv[KEYSERVER_DEFAULT_AES_GCM_IV_LEN];

    // =============================
    // Disk key information
    // =============================
    // The encrypted AES-XTS-256 disk key bytes
    uint8_t                         encrypted_aes_xts_256_disk_key[KEYSERVER_UDP_BUFFER_SIZE];

    // The number of encrypted AES-XTS-256 disk key bytes used in the
    // buffer `encrypted_aes_xts_256_disk_key`
    uint32_t                        encrypted_aes_xts_256_disk_key_len;

    // The AES-XTS-256 disk key bytes
    uint8_t                         aes_xts_256_disk_key[KEYSERVER_UDP_BUFFER_SIZE];

    // =============================
    // Boot image information
    // =============================
    char *                          initrd_command_line;
    char *                          kernel_command_line;
} keyserver_info_t;


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
    keyserver_info_t * the_keyserver);


// ***************************************************************************
/**
    @brief Handles state traversal based on messages received (or not
    received).
 
    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns 0 on successful keyserver completion, otherwise `-1`.
*/
int keyserver_process_state(
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    keyserver_info_t * the_keyserver);


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
    char ** the_ip_string);


// ***************************************************************************
/**
    @brief Opens a promiscuous UDP socket.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns `PXENV_EXIT_SUCCESS` on successful promiscuous UDP socket opening,
    otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t open_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver);


// ***************************************************************************
/**
    @brief Closes a promiscuous UDP socket.

    @param[in]  the_keyserver 
                    A keyserver structure used for state maintenance.

    @returns `PXENV_EXIT_SUCCESS` on successful closure of UDP socket,
    otherwise, `PXENV_EXIT_FAILURE`.
*/ 
PXENV_EXIT_t close_promiscuous_udp_socket(
    keyserver_info_t * the_keyserver);


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
    uint16_t * the_buffer_out_len);


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
    uint32_t the_seconds_timeout);


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
    uint16_t the_buffer_len);


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
    uint32_t the_data_len);

// ***************************************************************************
/**
    @brief Turn a string into an argv/argc representation by simply
    overwriting spaces with null terminators. 

    @warning This function assumes verbatim strings are passed in and does
    absolutely no "interpreter equivalent" escaping.

    @warning The input string will be be manipulated (spaces will be
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
    char ** the_argv_out);

#endif /* _IPXE_KEYSERVER_H */
