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

#include "vio_priv.h"
#include "my_context.h"
#include <mysql_async.h>
#include <ma_tls_vio.h>
#include <my_dir.h>

static uchar ma_tls_initialized= 0;

#if defined(HAVE_GNUTLS)
/* if we run in server mode, we will store specified ciphers in 
   the priority cache, since each connection will use the same
   priorities */
gnutls_priority_t priority_cache= 0;
MA_TLS_DH gnutls_dh= 0;
#endif

/* {{{ get_dh_2048 */
static int get_dh_2048(MA_TLS_DH *dh)
{
  static unsigned char dh2048_p[]={
    0xA1,0xBB,0x7C,0x20,0xC5,0x5B,0xC0,0x7B,0x21,0x8B,0xD6,0xA8,
    0x15,0xFC,0x3B,0xBA,0xAB,0x9F,0xDF,0x68,0xC4,0x79,0x78,0x0D,
    0xC1,0x12,0x64,0xE4,0x15,0xC9,0x66,0xDB,0xF6,0xCB,0xB3,0x39,
    0x02,0x5B,0x78,0x62,0xFB,0x09,0xAE,0x09,0x6B,0xDD,0xD4,0x5D,
    0x97,0xBC,0xDC,0x7F,0xE6,0xD6,0xF1,0xCB,0xF5,0xEB,0xDA,0xA7,
    0x2E,0x5A,0x43,0x2B,0xE9,0x40,0xE2,0x85,0x00,0x1C,0xC0,0x0A,
    0x98,0x77,0xA9,0x31,0xDE,0x0B,0x75,0x4D,0x1E,0x1F,0x16,0x83,
    0xCA,0xDE,0xBD,0x21,0xFC,0xC1,0x82,0x37,0x36,0x33,0x0B,0x66,
    0x06,0x3C,0xF3,0xAF,0x21,0x57,0x57,0x80,0xF6,0x94,0x1B,0xA9,
    0xD4,0xF6,0x8F,0x18,0x62,0x0E,0xC4,0x22,0xF9,0x5B,0x62,0xCC,
    0x3F,0x19,0x95,0xCF,0x4B,0x00,0xA6,0x6C,0x0B,0xAF,0x9F,0xD5,
    0xFA,0x3D,0x6D,0xDA,0x30,0x83,0x07,0x91,0xAC,0x15,0xFF,0x8F,
    0x59,0x54,0xEA,0x25,0xBC,0x4E,0xEB,0x6A,0x54,0xDF,0x75,0x09,
    0x72,0x0F,0xEF,0x23,0x70,0xE0,0xA8,0x04,0xEA,0xFF,0x90,0x54,
    0xCD,0x84,0x18,0xC0,0x75,0x91,0x99,0x0F,0xA1,0x78,0x0C,0x07,
    0xB7,0xC5,0xDE,0x55,0x06,0x7B,0x95,0x68,0x2C,0x33,0x39,0xBC,
    0x2C,0xD0,0x6D,0xDD,0xFA,0xDC,0xB5,0x8F,0x82,0x39,0xF8,0x67,
    0x44,0xF1,0xD8,0xF7,0x78,0x11,0x9A,0x77,0x9B,0x53,0x47,0xD6,
    0x2B,0x5D,0x67,0xB8,0xB7,0xBC,0xC1,0xD7,0x79,0x62,0x15,0xC2,
    0xC5,0x83,0x97,0xA7,0xF8,0xB4,0x9C,0xF6,0x8F,0x9A,0xC7,0xDA,
    0x1B,0xBB,0x87,0x07,0xA7,0x71,0xAD,0xB2,0x8A,0x50,0xF8,0x26,
    0x12,0xB7,0x3E,0x0B,
  };
  static unsigned char dh2048_g[]={
    0x02,
  };
#if defined(HAVE_OPENSSL)  

  if ((*dh=DH_new()) == NULL)
    return(ERR_get_error());
#if OPENSSL_VERSION_NUMBER < 0x10100000L
  dh->p=BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL);
  dh->g=BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
  if ((*dh->p == NULL) || (*dh->g == NULL))
  { DH_free(*dh); return ERR_get_error(); }
#else
  {
    BIGNUM *dhp_bn= BN_bin2bn(dh2048_p,sizeof(dh2048_p),NULL),
           *dhg_bn= BN_bin2bn(dh2048_g,sizeof(dh2048_g),NULL);
    if (dhp_bn == NULL || dhg_bn == NULL ||
        !DH_set0_pqg(*dh, dhp_bn, NULL, dhg_bn))
    {
      DH_free(*dh);
      BN_free(dhp_bn);
      BN_free(dhg_bn);
      return ERR_get_error();
    }
  }
#endif
  return 0;
#elif defined(HAVE_GNUTLS)
  int rc= 0;
  gnutls_datum_t prime, generator;
  prime.data= dh2048_p;
  prime.size= 256; /* 2048 bits */
  generator.data= dh2048_g;
  generator.size= 1;
  if ((rc= gnutls_dh_params_init(dh)) != GNUTLS_E_SUCCESS)
    return rc;
  rc= gnutls_dh_params_import_raw(*dh, &prime, &generator);
  return rc;
#endif
}
/* }}} */

#if defined(HAVE_OPENSSL)
int na_tls_openssl_passphrase_cb(char *buf, int size,
                                 int rwflag __attribute__((unused)),
                                 void *passphrase)
{
  strncpy(buf, (char *)passphrase, size);
  buf[size-1]= 0;
  return (int)strlen(buf);
}
#endif

/* {{{ ma_tls_ctx_load_key_cert */
ma_tls_error_t ma_tls_ctx_load_key_cert(MA_TLS_CTX ctx,
                                      const char *key_file,
                                      const char *cert_file,
                                      const char *passphrase __attribute__((unused)))
{
  char *key= (char *)key_file;
  char *cert= (char *)cert_file;
  int  lib_err;

  if (!key)
    cert= key;
  else if (!cert)
    key= cert;
#if defined(HAVE_OPENSSL)
  if (passphrase)
  {
    SSL_CTX_set_default_passwd_cb_userdata(ctx, (char *)passphrase);
    SSL_CTX_set_default_passwd_cb(ctx, na_tls_openssl_passphrase_cb);
  }
  if (cert &&
     (SSL_CTX_use_certificate_chain_file(ctx, cert)) <= 0)
  {
    lib_err= ERR_get_error();
    return (ma_tls_error_t){SSL_INITERR_CERT, lib_err};
  }
  if (key &&
      SSL_CTX_use_PrivateKey_file(ctx, key, SSL_FILETYPE_PEM) <= 0)
  {
    lib_err= ERR_get_error();
    return MA_TLS_ERROR(SSL_INITERR_KEY, lib_err);
  }
  if (cert && !SSL_CTX_check_private_key(ctx))
  {
    lib_err= ERR_get_error();
    return MA_TLS_ERROR(SSL_INITERR_NOMATCH, lib_err);
  }
#elif defined(HAVE_GNUTLS)
  lib_err= gnutls_certificate_set_x509_key_file2(ctx,
                                                cert,
                                                key,
                                                GNUTLS_X509_FMT_PEM,
                                                passphrase, 0);
  if (lib_err != GNUTLS_E_SUCCESS)
    return MA_TLS_ERROR(SSL_INITERR_NOMATCH, lib_err);
#endif
  return MA_TLS_ERROR(0,0);
}
/* }}} */

/* {{{ ma_tls_load_dh */
ma_tls_error_t ma_tls_load_dh(MA_TLS_CTX ctx __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  MA_TLS_DH dh;
#endif
  int rc;
#if defined(HAVE_OPENSSL)  
  if ((rc = get_dh_2048(&dh)))
#elif defined(HAVE_GNUTLS)
  if ((rc = get_dh_2048(&gnutls_dh)))
#endif
  {
    return MA_TLS_ERROR(SSL_INITERR_DH, rc);
  }
#if defined(HAVE_OPENSSL)
    if (!SSL_CTX_set_tmp_dh(ctx, dh))
    {
      rc= ERR_get_error();
      DH_free(dh);
      return MA_TLS_ERROR(SSL_INITERR_DH, rc);
    }
#elif defined(HAVE_GNUTLS)
  gnutls_certificate_set_dh_params(ctx, gnutls_dh);
#endif
  return MA_TLS_ERROR(0,0);
}
/* }}} */


#if defined(HAVE_OPENSSL)
/* {{{ my_asn1_time_to_string */
static char *
my_asn1_time_to_string(ASN1_TIME *time, char *buf, size_t len)
{
  int n_read;
  char *res= NULL;
  BIO *bio= BIO_new(BIO_s_mem());

  if (bio == NULL)
    return NULL;

  if (!ASN1_TIME_print(bio, time))
    goto end;

  n_read= BIO_read(bio, buf, (int) (len - 1));

  if (n_read > 0)
  {
    buf[n_read]= 0;
    res= buf;
  }

end:
  BIO_free(bio);
  return res;
}
/* }}} */
#elif defined(HAVE_GNUTLS)
extern const char *ma_gnutls_ciphername(gnutls_kx_algorithm_t kx,
                                        gnutls_cipher_algorithm_t cipher,
                                        gnutls_mac_algorithm_t mac);
#endif

/* {{{ ma_tls_verify_peer */
my_bool ma_tls_verify_peer(MA_TLS_SESSION sess)
{
#if defined(HAVE_OPENSSL)
  return SSL_get_verify_result(sess) == X509_V_OK;
#elif defined(HAVE_GNUTLS)
  unsigned int status;
  return gnutls_certificate_verify_peers2(sess, &status) == GNUTLS_E_SUCCESS;
#endif
}
/* }}} */

/* {{{ ma_tls_get_peer_cert */
int ma_tls_get_peer_cert(MA_TLS_SESSION sess, MA_TLS_CERT *cert)
{
#if defined(HAVE_OPENSSL)
  if (!(*cert= SSL_get_peer_certificate(sess)))
    return ERR_get_error();
#elif defined(HAVE_GNUTLS)
  int rc;
  unsigned int elements= 0;
  const gnutls_datum_t *cert_list;
  if (!(cert_list= gnutls_certificate_get_peers(sess, &elements)))
    return GNUTLS_E_NO_CERTIFICATE_FOUND;
  if ((rc = gnutls_x509_crt_init(cert)) < 0)
    return rc;
  if ((rc= gnutls_x509_crt_import(*cert, &cert_list[0], GNUTLS_X509_FMT_DER)) < 0)
  {
    gnutls_x509_crt_deinit(*cert);
    return rc;
  }
#endif
  return 0;
}
/* }}} */

/* {{{ ma_tls_cert_free */
void ma_tls_cert_free(MA_TLS_CERT cert)
{
#if defined(HAVE_OPENSSL)
  X509_free(cert);
#elif defined(HAVE_GNUTLS)
  gnutls_x509_crt_deinit(cert);
#endif
}
/* }}} */

/* {{{ ma_tls_get_info */
int ma_tls_get_info(enum ma_tls_info info,
                    enum ma_tls_info_type type,
                    void *context __attribute__((unused)),
                    void *data,
                    size_t *data_len)
{
  switch(info) {
  case MA_TLS_INFO_CIPHER_LIST:
  {
    char *buff= (type == MA_TLS_INFO_TYPE_CONST) ? 
                *((char **)data) : (char *)data;
#if defined(HAVE_OPENSSL)
    MA_TLS_SESSION sess= (MA_TLS_SESSION)context;
    int i;
    const char *p;
    size_t len= 0;
    *buff= 0;
    for (i=0; (p= SSL_get_cipher_list(sess,i)) &&
        len + strlen(p) + 1 < *data_len; i++)
    {
      strcat(buff, p);
      strcat(buff, ":");
      len= strlen(p) + 1;
    }
    if (i)
    {
      len--;
      buff[len]= 0;
    }
    *data_len= len;
#elif defined(HAVE_GNUTLS)
    const char *cipher;
    size_t len= 0;
    int i= 0;
    char *p= buff;

    while (len < *data_len &&
          ((cipher= tls_ciphers[i].openssl_name) ||
          (cipher= tls_ciphers[i].gnutls_name)))
    {
      if (strlen(cipher) + 2 < *data_len - len)
      {
        strcpy(p, cipher);
        p+= strlen(cipher);
        *p++= ':';
        len+= strlen(cipher) + 1;
      }
      else
        *data_len= len;
      i++;
    }
#endif
  }
  break;
  case MA_TLS_INFO_CERT_ISSUER:
  {
    MA_TLS_CERT cert= (MA_TLS_CERT)context;
#if defined(HAVE_OPENSSL)
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
    else
      strcpy((char *)data, X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0));
#elif defined(HAVE_GNUTLS)
    char *issuer;
    size_t size= 0;
    /* calculate size */
    gnutls_x509_crt_get_issuer_dn(cert, NULL, &size);
    issuer= (char *)malloc(size);
    gnutls_x509_crt_get_issuer_dn(cert, issuer, &size);
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((char **)data)= issuer;
    else
      strcpy((char *)data, issuer);
#endif
    break;
  }
  case MA_TLS_INFO_CERT_SUBJECT:
  {
    MA_TLS_CERT cert= (MA_TLS_CERT)context;
#if defined(HAVE_OPENSSL)
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
    else
      strcpy((char *)data, X509_NAME_oneline(X509_get_subject_name(cert), 0, 0));
#elif defined(HAVE_GNUTLS)
    char *subject;
    size_t size= 0;
    /* calculate size */
    gnutls_x509_crt_get_dn(cert, NULL, &size);
    subject= (char *)malloc(size);
    gnutls_x509_crt_get_dn(cert, subject, &size);
    *((char **)data)= subject;
#endif
    break;
  }
  case MA_TLS_INFO_VERSION:
  {
    MA_TLS_SESSION sess= (MA_TLS_SESSION)context;
#if defined(HAVE_OPENSSL)
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= SSL_get_version(sess);
    else
      strcpy((char *)data, SSL_get_version(sess));
#elif defined(HAVE_GNUTLS)
    gnutls_protocol_t p= gnutls_protocol_get_version(sess);
    *((const char **)data)= gnutls_protocol_get_name(p);
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= gnutls_protocol_get_name(p);
    else
      strcpy((char *)data, gnutls_protocol_get_name(p));
#endif
    break;
  }
  case MA_TLS_INFO_CIPHER:
  {
    MA_TLS_SESSION sess= (MA_TLS_SESSION)context;
#if defined(HAVE_OPENSSL)
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= SSL_get_cipher(sess);
    else
      strcpy((char *)data, SSL_get_cipher(sess));
#elif defined(HAVE_GNUTLS)
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((const char **)data)= ma_gnutls_ciphername(gnutls_kx_get(sess),
                                             gnutls_cipher_get(sess),
                                             gnutls_mac_get(sess));
    else
      strcpy((char *)data, ma_gnutls_ciphername(gnutls_kx_get(sess),
                                                gnutls_cipher_get(sess),
                                                gnutls_mac_get(sess)));

#endif
    break;
  }
  /* we currently don't support session resumption - so we set all
     values to zero for now */
  case MA_TLS_INFO_SESSION_CACHE_SIZE:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_get_cache_size((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_ACCEPT:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_accept((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_ACCEPT_RENEGOTIATE:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_accept_renegotiate((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_ACCEPT_GOOD:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_accept_good((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_NUMBER:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_number((MA_TLS_CTX)context);
#endif    
  case MA_TLS_INFO_SESSION_CACHE_TIMEOUTS:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_timeouts((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_MISSES:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_misses((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_FULL:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_cache_full((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_HITS:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_hits((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_CB_HITS:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_cb_hits((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_RENEGOTIATE:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_CTX_sess_accept_renegotiate((MA_TLS_CTX)context);
    break;
#endif
  case MA_TLS_INFO_SESSION_CACHE_REUSED:
#if defined(HAVE_OPENSSL)
     *(long *)data= SSL_session_reused((MA_TLS_SESSION)context);
#else
    *(long *)data= 0;
#endif    
    break;
  case MA_TLS_INFO_CERT_VALID_FROM:
  case MA_TLS_INFO_CERT_VALID_UNTIL:
  {
#if defined(HAVE_OPENSSL)
    MA_TLS_CERT cert= SSL_get_certificate((MA_TLS_SESSION)context);
    ASN1_TIME *asn1_time= 
     (info == MA_TLS_INFO_CERT_VALID_FROM) ?
      X509_get_notBefore(cert) : X509_get_notAfter(cert);
    if (type == MA_TLS_INFO_TYPE_CONST)
      *((char **)data)= my_asn1_time_to_string(asn1_time, *((char **)data), *data_len);
    else
      strcpy((char *)data, my_asn1_time_to_string(asn1_time, (char *)data, *data_len));
#elif defined(HAVE_GNUTLS)
    /* GNUTLS doesn't provide a mechanism to get the cert from context,
       so we need to access ctx internals */
    const gnutls_datum_t *der_cert= 
      gnutls_certificate_get_ours((MA_TLS_SESSION)context);
    MA_TLS_CERT cert;
    gnutls_x509_crt_init(&cert);
    if (data &&
      gnutls_x509_crt_import(cert, der_cert, GNUTLS_X509_FMT_DER) == GNUTLS_E_SUCCESS)
    {
      time_t t= (info == MA_TLS_INFO_CERT_VALID_FROM) ?
                gnutls_x509_crt_get_activation_time(cert) :
                gnutls_x509_crt_get_expiration_time(cert);
      struct tm *gmt= gmtime(&t);          
      strftime((type == MA_TLS_INFO_TYPE_CONST) ? *((char **)data) : (char *)data,
               *data_len, "%b %d %T %Y %Z", gmt);
    }
    gnutls_x509_crt_deinit(cert);
#endif
    break;
  }
  case MA_TLS_INFO_VERIFY_DEPTH:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_get_verify_depth((MA_TLS_SESSION)context);
#elif defined(HAVE_GNUTLS)
    *(long *)data= 0;
#endif
    break;
  case MA_TLS_INFO_VERIFY_MODE:
#if defined(HAVE_OPENSSL)
    *(long *)data= SSL_get_verify_mode((MA_TLS_SESSION)context);
#elif defined(HAVE_GNUTLS)
    *(long *)data= 0;
#endif
    break;
  case MA_TLS_INFO_TIMEOUT:
#if defined(HAVE_OPENSSL)
    *(long *)data= (long)SSL_get_default_timeout((MA_TLS_SESSION)context);
#elif defined(HAVE_GNUTLS)
    *(long *)data= 0;
#endif

  default:
    break;
  }
  return 0;
}
/* }}} */

/* {{{ ma_tls_has_data */
my_bool ma_tls_has_data(MA_TLS_SESSION sess)
{
#if defined(HAVE_OPENSSL)
  return SSL_pending(sess) > 0 ? TRUE : FALSE;
#elif defined(HAVE_GNUTLS)
  return gnutls_record_check_pending(sess) > 0 ? 
         TRUE : FALSE;
#endif
}
/* }}} */

/* {{{ static ma_tls_set_sys_error */
static void ma_tls_set_sys_error(int sess_error)
{
  int error= 0;
  switch(sess_error) {
#if defined(HAVE_OPENSSL)
  case SSL_ERROR_ZERO_RETURN:
    error= SOCKET_ECONNRESET;
    break;
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
#ifdef SSL_ERROR_WANT_CONNECT
  case SSL_ERROR_WANT_CONNECT:
#endif
#ifdef SSL_ERROR_WANT_ACCEPT
  case SSL_ERROR_WANT_ACCEPT:
#endif
    error= SOCKET_EWOULDBLOCK;
    break;
  case SSL_ERROR_SSL:
    /* Protocol error. */
#ifdef EPROTO
    error= EPROTO;
#else
    error= SOCKET_ECONNRESET;
#endif
    break;
#elif defined(HAVE_GNUTLS)
  case GNUTLS_E_UNEXPECTED_PACKET_LENGTH:
#ifdef EPROTO
    error= EPROTO;
#else
    error= SOCKET_ECONNRESET;
#endif
    break;
  case GNUTLS_E_AGAIN:
  case GNUTLS_E_INTERRUPTED:
    error= SOCKET_EWOULDBLOCK;
    break;
  default:
    break;
#endif
  }
  /* Set error status to a equivalent of the SSL error. */
  if (error)
  {
#ifdef _WIN32
    WSASetLastError(error);
#else
    errno= error;
#endif
  }
}
/* }}} */

/* {{{ ma_tls_should_retry */
my_bool ma_tls_should_retry(MA_TLS_SESSION sess, int ret, enum enum_vio_io_event *event)
{
  my_bool should_retry= TRUE;

#if defined(HAVE_OPENSSL)
  int sess_error;
  /* Retrieve the result for the SSL I/O operation. */
  sess_error= SSL_get_error(sess, ret);

  /* Retrieve the result for the SSL I/O operation. */
  switch (sess_error)
  {
  case SSL_ERROR_WANT_READ:
    *event= VIO_IO_EVENT_READ;
    break;
  case SSL_ERROR_WANT_WRITE:
    *event= VIO_IO_EVENT_WRITE;
    break;
  default:
    should_retry= FALSE;
    ma_tls_set_sys_error(sess_error);
    break;
  }
#elif defined(HAVE_GNUTLS)
  *event= (gnutls_record_get_direction(sess)) ?
          VIO_IO_EVENT_WRITE : VIO_IO_EVENT_READ;
  should_retry= (ret == GNUTLS_E_AGAIN || 
                 ret == GNUTLS_E_INTERRUPTED);
  if (!should_retry)
    ma_tls_set_sys_error(ret);
#endif
  return should_retry;
}
/* }}} */

/* {{{ ma_tls_read */
size_t ma_tls_read(MA_TLS_SESSION sess, unsigned char *buffer, size_t size)
{
#if defined(HAVE_OPENSSL)
  ERR_clear_error();
  return SSL_read(sess, buffer, size);
#elif defined(HAVE_GNUTLS)
  return gnutls_record_recv(sess, buffer, size);
#endif
}
/* }}} */

/* {{{ ma_tls_write */
size_t ma_tls_write(MA_TLS_SESSION sess, const unsigned char *buffer, size_t size)
{
#if defined(HAVE_OPENSSL)
  ERR_clear_error();
  return SSL_write(sess, buffer, size);
#elif defined(HAVE_GNUTLS)
  return gnutls_record_send(sess, buffer, size);
#endif
}
/* }}} */

/* {{{ ma_tls_sess_close */
void ma_tls_sess_close(MA_TLS_SESSION sess)
{
#if defined(HAVE_OPENSSL)
  int r= 0;
  if (!sess)
    return;
  /*
  THE SSL standard says that SSL sockets must send and receive a close_notify
  alert on socket shutdown to avoid truncation attacks. However, this can
  cause problems since we often hold a lock during shutdown and this IO can
  take an unbounded amount of time to complete. Since our packets are self
  describing with length, we aren't vunerable to these attacks. Therefore,
  we just shutdown by closing the socket (quiet shutdown).
  */
  SSL_set_quiet_shutdown(sess, 1); 
  
  switch ((r= SSL_shutdown(sess))) {
  case 1:
    /* Shutdown successful */
    break;
  case 0:
    /*
      Shutdown not yet finished - since the socket is going to
      be closed there is no need to call SSL_shutdown() a second
      time to wait for the other side to respond
    */
    break;
  default: /* Shutdown failed */
    DBUG_PRINT("vio_error", ("SSL_shutdown() failed, error: %d",
                             SSL_get_error(sess, r)));
    break;
  }
#elif defined(HAVE_GNUTLS)
  if (sess)
    gnutls_bye(sess, GNUTLS_SHUT_WR);
#endif
}
/* }}} */

/* {{{ ma_tls_sess_free */
void ma_tls_sess_free(MA_TLS_SESSION sess)
{
#if defined(HAVE_OPENSSL)
  SSL_free(sess);
#elif defined(HAVE_GNUTLS)
  gnutls_deinit(sess);
#endif
}
/* }}} */

/* {{{ ma_tls_ctx_new */
int ma_tls_ctx_new(MA_TLS_CTX *ctx,
                   int type __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
#if OPENSSL_VERSION_NUMBER >= 0x10100000L
  if (!(*ctx= SSL_CTX_new(type == MA_TLS_SERVER ? 
                   TLS_server_method() : TLS_client_method())))
    return ERR_get_error();
#else
  if (!(*ctx= SSL_CTX_new(type == MA_TLS_SERVER ? 
                   SSLv23_server_method() : SSLv23_client_method())))
  return ERR_get_error();
  /* disable SSLv2 and SSLv3 */
  SSL_CTX_set_options(*ctx, SSL_OP_NO_SSLv3 | SSL_OP_NO_SSLv2);
#endif
  return 0;
#elif defined(HAVE_GNUTLS)
  return gnutls_certificate_allocate_credentials(ctx);
#endif
}
/* }}} */

/* {{{ ma_tls_ctx_free */
void ma_tls_ctx_free(MA_TLS_CTX ctx)
{
#if defined(HAVE_OPENSSL)
  SSL_CTX_free(ctx);
#elif defined(HAVE_GNUTLS)
  if (gnutls_dh)
    gnutls_dh_params_deinit(gnutls_dh);
  gnutls_certificate_free_cas(ctx);
  gnutls_certificate_free_crls(ctx);
  gnutls_certificate_free_keys(ctx);
  gnutls_certificate_free_credentials(ctx);
#endif
}
/* }}} */

/* {{{ ma_tls_sess_new */
int ma_tls_sess_new(MA_TLS_SESSION *sess __attribute__((unused)),
                    MA_TLS_CTX ctx __attribute__((unused)),
                    unsigned int flags __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  if (!(*sess= SSL_new(ctx)))
    return ERR_get_error();
  return 0;
#elif defined(HAVE_GNUTLS)
  int mode= GNUTLS_NONBLOCK;
  mode|= (flags == MA_TLS_SERVER) ? GNUTLS_SERVER : GNUTLS_CLIENT;
  return gnutls_init(sess, mode);
  gnutls_certificate_server_set_request(*sess, GNUTLS_CERT_REQUEST);
#endif
}
/* }}} */

/* {{{ ma_tls_sess_transport_set */
int ma_tls_sess_transport_set(MA_TLS_SESSION sess,
                              void *data,
                              ma_tls_transport_func_t read __attribute__((unused)),
                              ma_tls_transport_func_t write __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  if (!read || !write)
  {
    int fd= *(int *)data;
    SSL_clear(sess);
#if defined(SSL_OP_NO_COMPRESSION)
    SSL_set_options(sess, SSL_OP_NO_COMPRESSION);
#endif
    if (!SSL_set_fd(sess, fd))
      return ERR_get_error();
  }
#elif defined(HAVE_GNUTLS)
  if (!read || !write)
  {
    int fd= *(int *)data;
    gnutls_transport_set_int(sess, fd);
    return 0;
  }
#endif
  return 0;
}
/* }}} */

/* {{{ ma_tls_transport_get_int */
int ma_tls_transport_get_int(MA_TLS_SESSION sess)
{
#if defined(HAVE_OPENSSL)
  return SSL_get_fd(sess);
#elif defined(HAVE_GNUTLS)
  return gnutls_transport_get_int(sess);
#endif
}
/* }}} */

/* {{{ ma_tls_handshake */
int ma_tls_handshake(MA_TLS_SESSION sess,
                     int type __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  return (type == MA_TLS_SERVER) ?
         SSL_accept(sess) : SSL_connect(sess);
#elif defined(HAVE_GNUTLS)
  /* GnuTLS sets connection type already during init */
  int rc= gnutls_handshake(sess);
  return (!rc) ? 1 : rc;
#endif
}
/* }}} */

/* {{{ ma_tls_init */
void ma_tls_init()
{
  if (!ma_tls_initialized)
  {
    ma_tls_initialized= 1;
#if defined(HAVE_OPENSSL)
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();
#elif defined(HAVE_GNUTLS)
    gnutls_global_init();
#endif
  }
}
/* }}} */

#if defined(HAVE_GNUTLS)
static char *ma_gnutls_get_priority(char *cipher_str)
{
  char *token;
#define PRIO_SIZE 1024  
  char *prio= malloc(PRIO_SIZE);

  if (!cipher_str) {
    strcpy(prio, "NORMAL");
    goto end;
  }

  token= strtok(cipher_str, ":");

  strcpy(prio, "NONE:+VERS-TLS-ALL:+SIGN-ALL:+COMP-NULL");

  while (token)
  {
    const char *p= ma_gnutls_get_priority(token);
    if (p)
      strncat(prio, p, PRIO_SIZE - strlen(prio) - 1);
    token = strtok(NULL, ":");
  }
end:
  return prio;
}
#endif

int ma_tls_sess_set_cipher(MA_TLS_SESSION sess __attribute__((unused)),
                           const char *cipher __attribute__((unused)),
                           int type __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  return 0;
#elif defined(HAVE_GNUTLS)
  char *prio= NULL;
  int rc;
  if ((type == MA_TLS_SERVER && !priority_cache) ||
      (type == MA_TLS_CLIENT))
  {
    prio= ma_gnutls_get_priority((char *)cipher);
    if (type == MA_TLS_SERVER)
      if ((rc= gnutls_priority_init(&priority_cache, prio, NULL)))
        goto end;
  }
  if (type == MA_TLS_SERVER)
    rc= gnutls_priority_set(sess, priority_cache);
  else
    rc= gnutls_priority_set_direct(sess, prio, NULL);
end:
  if (prio)
    free(prio);
  return rc;    
#endif
}

/* {{{ ma_tls_ctx_set_cipher */
int ma_tls_ctx_set_cipher(MA_TLS_CTX ctx __attribute__((unused)),
                          const char *cipher __attribute__((unused)),
                          int type __attribute__((unused)))
{
  int rc= 0;
#if defined(HAVE_OPENSSL)
  if (!SSL_CTX_set_cipher_list(ctx, cipher))
    rc= ERR_get_error();
#elif defined(HAVE_GNUTLS)
  /* we set this later in session */
  if (type == MA_TLS_SERVER)
  {

  }
  return 1;
#endif
  return rc;
}
/* }}} */

/* {{{ ma_tls_ctx_load_ca */
ma_tls_error_t ma_tls_ctx_load_ca(MA_TLS_CTX ctx,
                                  const char *ca_file,
                                  const char *ca_path)
{
#if defined(HAVE_OPENSSL)
  if ((SSL_CTX_load_verify_locations(ctx, ca_file, ca_path)) <= 0)
  {
    if (ca_file || ca_path)
      return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, ERR_get_error());

    if (SSL_CTX_set_default_verify_paths(ctx) == 0)
      return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, ERR_get_error());
  }
#elif defined(HAVE_GNUTLS)
  if (ca_file &&
      (gnutls_certificate_set_x509_trust_file(ctx, ca_file, GNUTLS_X509_FMT_PEM) < 1))
    return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, GNUTLS_E_FILE_ERROR);
  if (ca_path)
  {
    if (gnutls_certificate_set_x509_trust_dir(ctx, ca_path, GNUTLS_X509_FMT_PEM) < 1)
      return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, GNUTLS_E_FILE_ERROR);
  }
#endif
  return MA_TLS_ERROR(0,0);
}
/* }}} */

/* {{{ ma_tls_ctx_load_crl */
ma_tls_error_t ma_tls_ctx_load_crl(MA_TLS_CTX ctx,
                       const char *crl_file,
                       const char *crl_path)
{
#if defined(HAVE_OPENSSL)
  X509_STORE *store= SSL_CTX_get_cert_store(ctx);
  if (!store)
    return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, ERR_get_error());
  if (X509_STORE_load_locations(store, crl_file, crl_path) == 0 ||
      X509_STORE_set_flags(store,
                           X509_V_FLAG_CRL_CHECK | 
                           X509_V_FLAG_CRL_CHECK_ALL) == 0)
    return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, ERR_get_error());
#elif defined(HAVE_GNUTLS)
  int rc;
  if (crl_file && (rc= gnutls_certificate_set_x509_crl_file(ctx,
                         crl_file, GNUTLS_X509_FMT_PEM)))
    return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, rc);
  /* GnuTLS doesn't support ca-path, so 
     we abort with error */
  if (crl_path)
  {
    MY_DIR *dirp= my_dir(crl_path, 0);
    unsigned int i;
    if (!dirp)
    {
      DBUG_PRINT("error", ("invalid crl_path")); 
      return MA_TLS_ERROR(SSL_INITERR_BAD_PATHS, 0);
    }
    for (i=0; i < (uint)dirp->number_of_files; i++)
    {
      FILEINFO *file= dirp->dir_entry+i;
      if (strlen(file->name) > 4)
      {
        char *p= file->name + strlen(file->name) - 4;
        if (!strncasecmp(p, ".pem", 4))
          gnutls_certificate_set_x509_crl_file(ctx,
          file->name, GNUTLS_X509_FMT_PEM);
      }
    }
    my_dirend(dirp);
  }
#endif
  return MA_TLS_ERROR(0,0);
}
/* }}} */

/* {{{ ma_tls_ctx_set_sess_cache_size */
int ma_tls_ctx_set_sess_cache_size(MA_TLS_CTX ctx __attribute__((unused)),
                                   size_t size __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  SSL_CTX_sess_set_cache_size(ctx, 128);
  return ERR_get_error();
#elif defined(HAVE_GNUTLS)
  return 0;
#endif
}
/* }}} */

/* {{{ ma_tls_ctx_set_sess_id_context */
int ma_tls_ctx_set_sess_id_context(MA_TLS_CTX ctx __attribute__((unused)),
                                   const unsigned char *sid __attribute__((unused)),
                                   size_t sid_len __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  SSL_CTX_set_session_id_context(ctx, sid, sid_len);
  return ERR_get_error();
#elif defined(HAVE_GNUTLS)
  return 0;
#endif
}
/* }}} */

/* {{{ ma_tls_ctx_set_verify */
void ma_tls_ctx_set_verify(MA_TLS_CTX ctx __attribute__((unused)))
{
#if defined(HAVE_OPENSSL)
  int verify= SSL_VERIFY_PEER | SSL_VERIFY_CLIENT_ONCE;
  SSL_CTX_set_verify(ctx, verify, NULL);
#elif defined(HAVE_GNUTLS)
#endif
}

/* {{{ ma_tls_set_ctx */
void ma_tls_set_context(MA_TLS_SESSION sess __attribute__((unused)),
                        MA_TLS_CTX ctx __attribute__((unused)))
{
#if defined(HAVE_GNUTLS)
  gnutls_credentials_set(sess, GNUTLS_CRD_CERTIFICATE, (void *)ctx);
#endif
}
