/* Copyright (c) 2000, 2016, Oracle and/or its affiliates.
   Copyright (c) 2011, 2016, MariaDB

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; version 2 of the License.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301  USA */

#ifdef HAVE_TLS

#include "vio_priv.h"
#include "ma_tls_vio.h"


static const char*
ssl_error_string[] = 
{
  "No error",
  "Unable to get certificate",
  "Unable to get private key",
  "Private key does not match the certificate public key",
  "SSL_CTX_set_default_verify_paths failed",
  "Failed to set ciphers to use",
  "SSL_CTX_new failed",
  "SSL_CTX_set_tmp_dh failed"
};

const char*
sslGetErrString(enum enum_ssl_init_error e)
{
  DBUG_ASSERT(SSL_INITERR_NOERROR < e && e < SSL_INITERR_LASTERR);
  return ssl_error_string[e];
}

static void check_ssl_init()
{
  ma_tls_init();
}

/************************ VioSSLFd **********************************/
static struct st_VioSSLFd *
new_VioSSLFd(const char *key_file, const char *cert_file,
             const char *ca_file, const char *ca_path,
             const char *cipher, my_bool is_client_method,
             enum enum_ssl_init_error *error,
             const char *crl_file, const char *crl_path,
             const char *passphrase)
{
  struct st_VioSSLFd *ssl_fd;
  ma_tls_error_t err;
  DBUG_ENTER("new_VioSSLFd");
  DBUG_PRINT("enter",
             ("key_file: '%s'  cert_file: '%s'  ca_file: '%s'  ca_path: '%s'  "
              "cipher: '%s' crl_file: '%s' crl_path: '%s' ",
              key_file ? key_file : "NULL",
              cert_file ? cert_file : "NULL",
              ca_file ? ca_file : "NULL",
              ca_path ? ca_path : "NULL",
              cipher ? cipher : "NULL",
              crl_file ? crl_file : "NULL",
              crl_path ? crl_path : "NULL"));

  check_ssl_init();

  if (!(ssl_fd= ((struct st_VioSSLFd*)
                 my_malloc(sizeof(struct st_VioSSLFd),MYF(0)))))
    goto err0;

  if (ma_tls_ctx_new(&ssl_fd->ssl_context, is_client_method ?
                     MA_TLS_CLIENT : MA_TLS_SERVER))
  {
    *error= SSL_INITERR_MEMFAIL;
    DBUG_PRINT("error", ("%s", sslGetErrString(*error)));
    goto err1;
  }

  /*
    Set the ciphers that can be used
    NOTE: SSL_CTX_set_cipher_list will return 0 if
    none of the provided ciphers could be selected.

    If we run in server mode, gnutls will use it's priority cache 
  */
  if (cipher && ma_tls_ctx_set_cipher(ssl_fd->ssl_context,
                                      cipher,
                                      is_client_method ?
                                      MA_TLS_CLIENT : MA_TLS_SERVER) != 0)
  {
    *error= SSL_INITERR_CIPHERS;
    DBUG_PRINT("error", ("%s", sslGetErrString(*error)));
    goto err2;
  }
#if !defined(HAVE_OPENSSL)
  ssl_fd->cipher= cipher;
#endif

  err= ma_tls_ctx_load_ca(ssl_fd->ssl_context, ca_file, ca_path);
  if ((*error= err.tls_err))
  {
    printf("error: %d\n", err.lib_err);
    DBUG_PRINT("warning", ("ma_tls_ctx_load_ca filed"));
    goto err2;
  }

  if (crl_file || crl_path)
  {
     err= ma_tls_ctx_load_crl(ssl_fd->ssl_context, crl_file, crl_path);
     if ((*error= err.tls_err))
     {
       DBUG_PRINT("warning", ("ma_tls_ctx_load_crl filed"));
       goto err2;
     }
  }

  err= ma_tls_ctx_load_key_cert(ssl_fd->ssl_context, key_file, cert_file,
                                passphrase);
  if ((*error= err.tls_err))
  {
    DBUG_PRINT("error", ("vio_set_cert_stuff failed"));
    goto err2;
  }

  /* DH stuff */
  if (!is_client_method)
  {
    err= ma_tls_load_dh(ssl_fd->ssl_context);
    if ((*error= err.tls_err))
      goto err2;
  }

  DBUG_PRINT("exit", ("OK 1"));

  DBUG_RETURN(ssl_fd);

err2:
  ma_tls_ctx_free(ssl_fd->ssl_context);
err1:
  my_free(ssl_fd);
err0:
#ifdef HAVE_OPENSSL
  DBUG_EXECUTE("error", ERR_print_errors_fp(DBUG_FILE););
#endif
  
  DBUG_RETURN(0);
}


/************************ VioSSLConnectorFd **********************************/
struct st_VioSSLFd *
new_VioSSLConnectorFd(const char *key_file, const char *cert_file,
                      const char *ca_file, const char *ca_path,
                      const char *cipher, enum enum_ssl_init_error* error,
                      const char *crl_file, const char *crl_path,
                      const char *passphrase)
{
  struct st_VioSSLFd *ssl_fd;
#if defined(HAVE_OPENSSL)
  int verify= SSL_VERIFY_PEER;

  /*
    Turn off verification of servers certificate if both
    ca_file and ca_path is set to NULL
  */
  if (ca_file == 0 && ca_path == 0)
    verify= SSL_VERIFY_NONE;
#endif

  if (!(ssl_fd= new_VioSSLFd(key_file, cert_file, ca_file,
                             ca_path, cipher, TRUE, error,
                             crl_file, crl_path, passphrase)))
  {
    return 0;
  }

  /* Init the VioSSLFd as a "connector" ie. the client side */
#if defined(HAVE_OPENSSL)
  SSL_CTX_set_verify(ssl_fd->ssl_context, verify, NULL);
#endif
  return ssl_fd;
}


/************************ VioSSLAcceptorFd **********************************/
struct st_VioSSLFd *
new_VioSSLAcceptorFd(const char *key_file, const char *cert_file,
		     const char *ca_file, const char *ca_path,
		     const char *cipher, enum enum_ssl_init_error* error,
                     const char *crl_file, const char *crl_path,
                     const char *passphrase)
{
  struct st_VioSSLFd *ssl_fd;
  if (!(ssl_fd= new_VioSSLFd(key_file, cert_file, ca_file,
                             ca_path, cipher, FALSE, error,
                             crl_file, crl_path, passphrase)))
  {
    return 0;
  }

  /* Set max number of cached sessions, returns the previous size */
  ma_tls_ctx_set_sess_cache_size(ssl_fd->ssl_context, 128);
  ma_tls_ctx_set_verify(ssl_fd->ssl_context);

  /*
    Set session_id - an identifier for this server session
    Use the ssl_fd pointer
   */
  ma_tls_ctx_set_sess_id_context(ssl_fd->ssl_context,
                                 (const unsigned char *)ssl_fd,
                                 sizeof(ssl_fd));

  return ssl_fd;
}

void free_vio_ssl_acceptor_fd(struct st_VioSSLFd *fd)
{
  ma_tls_ctx_free(fd->ssl_context);
  my_free(fd);
}
#endif /* HAVE_OPENSSL */
