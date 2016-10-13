/* Copyright (c) 2016 Georg Richter and MariaDB Corporation AB

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Library General Public
   License as published by the Free Software Foundation; either
   version 2 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Library General Public
   License along with this library; if not see <http://www.gnu.org/licenses>
   or write to the Free Software Foundation, Inc., 
   51 Franklin St., Fifth Floor, Boston, MA 02110, USA */

#ifndef _ma_tls_vio_h
#define _ma_tls_vio_h
#ifdef HAVE_TLS

#if defined(HAVE_OPENSSL)

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/dh.h>
#include <openssl/bn.h>

typedef SSL_CTX * MA_TLS_CTX;
typedef SSL *     MA_TLS_SESSION;
typedef X509 *    MA_TLS_CERT;
typedef DH *      MA_TLS_DH;

#define GNUTLS_CIPHER(A,B,C,D)

#elif defined(HAVE_GNUTLS)

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

typedef gnutls_session_t                 MA_TLS_SESSION;
typedef gnutls_x509_crt_t                MA_TLS_CERT;
typedef gnutls_certificate_credentials_t MA_TLS_CTX;
typedef gnutls_dh_params_t               MA_TLS_DH;

typedef gnutls_kx_algorithm_t            MA_TLS_KX_ALG;
typedef gnutls_cipher_algorithm_t        MA_TLS_CIPHER_ALG;
typedef gnutls_mac_algorithm_t           MA_TLS_MAC_ALG;

#define GNUTLS_CIPHER(A,B,C,D) (A),(B),(C),(D)
extern gnutls_priority_t priority_cache;
#endif

struct st_cipher_map {
  const char *openssl_name;
  const char *gnutls_name;
#if defined(HAVE_GNUTLS)  
  const char *priority;
#endif  
#if !defined(HAVE_OPENSSL)
  /* In GnuTLS and Schannel we need to identify the cipher name
     via key_exchange, cipher and mac algorithm */
  MA_TLS_KX_ALG kx;
  MA_TLS_CIPHER_ALG cipher;
  MA_TLS_MAC_ALG mac;
#endif
};

typedef struct st_ma_tls_error {
  int tls_err;
  int lib_err;
} ma_tls_error_t;

#define MA_TLS_ERROR(a,b) (ma_tls_error_t){(a),(b)}

extern const struct st_cipher_map tls_ciphers[];

enum ma_tls_info {
  MA_TLS_INFO_VERSION= 0,
  MA_TLS_INFO_SESSION_CACHE_SIZE,
  MA_TLS_INFO_SESSION_CACHE_NUMBER,
  MA_TLS_INFO_SESSION_CACHE_TIMEOUTS,
  MA_TLS_INFO_SESSION_CACHE_MISSES,
  MA_TLS_INFO_SESSION_CACHE_FULL,
  MA_TLS_INFO_SESSION_CACHE_HITS,
  MA_TLS_INFO_SESSION_CACHE_CB_HITS,
  MA_TLS_INFO_SESSION_CACHE_ACCEPT,
  MA_TLS_INFO_SESSION_CACHE_ACCEPT_GOOD,
  MA_TLS_INFO_SESSION_CACHE_ACCEPT_RENEGOTIATE,
  MA_TLS_INFO_SESSION_CACHE_REUSED,
  MA_TLS_INFO_SESSION_TIMEOUT,       
  MA_TLS_INFO_VERIFY_MODE,
  MA_TLS_INFO_VERIFY_DEPTH,
  MA_TLS_INFO_CIPHER,
  MA_TLS_INFO_CIPHER_LIST,
  MA_TLS_INFO_CERT_ISSUER,
  MA_TLS_INFO_CERT_SUBJECT,
  MA_TLS_INFO_CERT_VALID_FROM,
  MA_TLS_INFO_CERT_VALID_UNTIL,
  MA_TLS_INFO_SESSION_CACHE_RENEGOTIATE,
  MA_TLS_INFO_TIMEOUT,
};

enum ma_tls_info_type {
  MA_TLS_INFO_TYPE_LONG,
  MA_TLS_INFO_TYPE_CONST,
  MA_TLS_INFO_TYPE_CHAR
};
#define MA_TLS_CLIENT   1
#define MA_TLS_SERVER   2

#ifdef __cplusplus
extern "C" {
#endif
/**
  @brief
  Retrieves first certificate from peer.
  The certificate must be freed with ma_tls_cert_free

  @param[in]      session     current tls session
  @param[out]     cert        certificate pointer

  @return         0 on success,
                  non zero for error
*/
int ma_tls_get_peer_cert(MA_TLS_SESSION session, MA_TLS_CERT *cert);

/**
  @brief
  Frees a certificate which was previously obtained by ma_tls_get_peer_cert.

  @param          cert   certificate 

  @return         void
*/
void ma_tls_cert_free(MA_TLS_CERT cert);

int ma_tls_transport_get_int(MA_TLS_SESSION sess);

/**
  @brief        verifies the X509 certificate presented by peer

  @param[in]    tls session

  @return       true on success, otherwise false
*/
my_bool ma_tls_verify_peer(MA_TLS_SESSION session);

int ma_tls_get_info(enum ma_tls_info info,
                    enum ma_tls_info_type type,
                    void *context,
                    void *data,
                    size_t *data_len);

/**
  @brief        check if there is data available for immediate read

  @param[in]    sess     current TLS session

  @return       true     if data for read is available
                false    if no data is available
*/
my_bool ma_tls_has_data(MA_TLS_SESSION sess);

//void ma_tls_set_sys_error(int sslerror);
/**
  @brief     checks error code after handshake operation

  @param[in]       session  current TLS session
  @param[in]       ret      return code from previous handshake event
  @param[out]      event    read or write event

  @return          true     if handshake should be repeated
                   false    on error
*/
my_bool ma_tls_should_retry(MA_TLS_SESSION sess, int ret, 
                            enum enum_vio_io_event *event);

/**
  @brief           reads up tp size bytes from transport ptr of  the current session

  @param[in]       session  current TLS session
  @param[out]      buffer   read buffer
  @param[in]       size     size of the buffer

  @return          number of bytes read into buffer
*/
size_t ma_tls_read(MA_TLS_SESSION sess, unsigned char *buffer, size_t size);

/**
  @brief           writes up tp size bytes from transport ptr of  the current session

  @param[in]       session  current TLS session
  @param[in]       buffer   buffer which contains data
  @param[in]       size     size of the buffer

  @return          number of bytes read into buffer
*/
size_t ma_tls_write(MA_TLS_SESSION sess, const unsigned char *buffer, size_t size);

/**
  @brief      creates a new session handle which is needed to hold the
              data for a TLS connection. Depending on the tls library in use
              the handle may inherit the settings of the underlying session
              context ctx.
              The created session handle must be freed with 
              ma_tls_session_free().

  @param[in]  pointer to a TLS session handle
  @param[in]  session context
  @param[in]  type (server or client, non blocking)

  @return     session handle
*/
int ma_tls_sess_new(MA_TLS_SESSION *sess __attribute__((unused)),
                    MA_TLS_CTX ctx __attribute__((unused)),
                    unsigned int flags __attribute__((unused)));

typedef size_t (*ma_tls_transport_func_t)(void *, unsigned char *, size_t);
/**
  @brief      sets the transport mechanism for a TLS session

  @param[in]  data    A pointer to a 
*/
int ma_tls_sess_transport_set(MA_TLS_SESSION sess,
                              void *data,
                              ma_tls_transport_func_t read __attribute__((unused)),
                              ma_tls_transport_func_t write __attribute__((unused)));

                          
/**
  @brief     closes the current session

  @param[in]  sess     current TLS session

  @return     void
*/
void ma_tls_sess_close(MA_TLS_SESSION sess);

/**
  @brief      frees up memory assiciated with the specified session

  @param[in]  current TLS session

  @return     void
*/
void ma_tls_sess_free(MA_TLS_SESSION sess);
/**
  @brief      performs the handshake of the specified TLS session and
              initializes the TLS connection.

  @param[in]  session   the session on which 
  @param[in]  type      optional: server or client flags,
                                  nonblock flag

  @return     0 on success
              other error code
*/
int ma_tls_handshake(MA_TLS_SESSION sess,
                     int flags __attribute__((unused)));

/**
  @brief           creates a new MA_TLS_CTX context used for TLS connections.

  @param[in][out]  ctx   a pointer to a MA_TLS_CTX context.
  @param[in]       flags some tls libraries require additional flags, e.g. for
                         specifying client/server mode

  @return          0 on success
                   non zero for error
*/
int ma_tls_ctx_new(MA_TLS_CTX *ctx,
                   int type __attribute__((unused)));

/**
  @brief           frees up the specified context

  @param[in]       ctx      context

  @return          void
*/
void ma_tls_ctx_free(MA_TLS_CTX ctx);

/**
  @brief           initializes the TLS library
*/
void ma_tls_init();

/**
  @brief                Sets cipher for given context

  @param [in]   ctx     context
  @param [in]   cipher  cipher(s) to set. Multiple ciphers can be concatenated
                        by ":"
  @param [in]   type    context type: server of client

  @return       0 on success
                non zero on error
*/
int ma_tls_ctx_set_cipher(MA_TLS_CTX ctx,
                          const char *cipher,
                          int type __attribute__((unused)));
/**
  @brief                Sets cipher for given session

  @param [in]   ctx     session
  @param [in]   cipher  cipher(s) to set. Multiple ciphers can be concatenated
                        by ":"
  @param [in]   type    session type: server of client

  @return       0 on success
                non zero on error
*/

int ma_tls_sess_set_cipher(MA_TLS_SESSION sess __attribute__((unused)),
                           const char *cipher __attribute__((unused)),
                           int type __attribute__((unused)));
/**
  @brief      Sets dh parameters for the given context.
              The dh key is inherited by all sessions created
              from context
  @param [in] session context

  @returns    ma_tls_error_t error structure
*/ 
ma_tls_error_t ma_tls_load_dh(MA_TLS_CTX ctx __attribute__((unused)));

/**
  @brief      loads certifcates from trusted ca

  @param [in] ctx      context
  @param [in] ca_file  ca file
  @param [in] ca_path  ca path (this parameter isn't supported
                       by all TLS libraries)

  @return     0 on success
              non zero on error
*/
ma_tls_error_t ma_tls_ctx_load_ca(MA_TLS_CTX ctx,
                                  const char *ca_file,
                                  const char *ca_path);

/**
  @brief      loads certifcate revocation lists 

  @param [in] ctx      context
  @param [in] ca_file  crl file
  @param [in] ca_path  crl path (this parameter isn't supported
                       by all TLS libraries)

  @return     0 on success
              non zero on error
*/
ma_tls_error_t ma_tls_ctx_load_crl(MA_TLS_CTX ctx,
                                   const char *crl_file,
                                   const char *crl_path);
/**
  @brief      set size of session cache. This function might not be
              supported by all TLS libraries

  @param[in]  ctx      TLS session context
  @param[in]  size     size of context

  @return     0 on success,
              non zero if an error occured
*/
int ma_tls_ctx_set_sess_cache_size(MA_TLS_CTX ctx, size_t size);

/**
  @brief      sets the context id  within which a session can be reused for
              the ctx object (server only)

  @param[in]  ctx       session context
  @param[in]  sid       session id
  @param[in]  sid_len   length of session id

  @return     0 on success,
              non zero on error
*/
int ma_tls_ctx_set_sess_id_context(MA_TLS_CTX ctx,
                                   const unsigned char *sid,
                                   size_t sid_len);
/**
  @brief   Load key and certificate in TLS context. Key and certificate
           files must be in PEM format.

  @param[in]   ctx        TLS context
  @param[in]   key_file   filename of private key
  @param[in]   cert_file  filename of certificate
  @param[in]   passphrase Passphrase for private key

  @return      a ma_tls_error_t structure
*/
ma_tls_error_t ma_tls_ctx_load_key_cert(MA_TLS_CTX ctx,
                                        const char *key_file,
                                        const char *cert_file,
                                        const char *passphrase);

/**
  @brief      Set TLS context for session

  @param[in]  sess    session
  @param[in]  ctx     tls context

  @return     void
*/
void ma_tls_set_context(MA_TLS_SESSION session,
                        MA_TLS_CTX ctx);

/**
  @brief      Set verification options (server mode only)

  @param[in]  ctx   TLS context

  @return     void
*/
void ma_tls_ctx_set_verify(MA_TLS_CTX ctx __attribute__((unused)));
#if defined(HAVE_GNUTLS)
const char *ma_tls_get_priority_name(char *cipher_name);
#endif
#ifdef __cplusplus
}
#endif

#endif /* HAVE_TLS */
#endif /* _ma_tls_vio_h */
