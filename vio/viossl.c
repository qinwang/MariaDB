/* Copyright (c) 2000, 2013, Oracle and/or its affiliates. All rights reserved.

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

/*
  Note that we can't have assertion on file descriptors;  The reason for
  this is that during mysql shutdown, another thread can close a file
  we are working on.  In this case we should just return read errors from
  the file descriptior.
*/

#include "vio_priv.h"
#include "my_context.h"
#include <mysql_async.h>
#include <ma_tls_vio.h>

#ifdef HAVE_TLS

/**
  Indicate whether a SSL I/O operation must be retried later.

  @param vio  VIO object representing a SSL connection.
  @param ret  Value returned by a SSL I/O function.
  @param event[out] The type of I/O event to wait/retry.

  @return Whether a SSL I/O operation should be deferred.
  @retval TRUE    Temporary failure, retry operation.
  @retval FALSE   Indeterminate failure.
*/

size_t vio_ssl_read(Vio *vio, uchar *buf, size_t size)
{
  int ret;
  MA_TLS_SESSION sess= vio->ssl_arg;
  DBUG_ENTER("vio_ssl_read");
  DBUG_PRINT("enter", ("sd: %d  buf: %p  size: %d  ssl: %p",
		       mysql_socket_getfd(vio->mysql_socket), buf, (int) size,
                       vio->ssl_arg));

  if (vio->async_context && vio->async_context->active)
    ret= my_ssl_read_async(vio->async_context, vio->ssl_arg, buf, size);
  else
  {
    while ((ret= ma_tls_read(sess, buf, size)) < 0)
    {
      enum enum_vio_io_event event;
      
      /* Process the SSL I/O error. */
      if (!ma_tls_should_retry(vio->ssl_arg, ret, &event))
        break;
      /* Attempt to wait for an I/O event. */
      if (vio_socket_io_wait(vio, event))
        break;
    }
  }

  DBUG_PRINT("exit", ("%d", (int) ret));
  DBUG_RETURN(ret < 0 ? -1 : ret);

}


size_t vio_ssl_write(Vio *vio, const uchar *buf, size_t size)
{
  int ret;
  MA_TLS_SESSION sess= vio->ssl_arg;
  DBUG_ENTER("vio_ssl_write");
  DBUG_PRINT("enter", ("sd: %d  buf: %p  size: %d",
                       mysql_socket_getfd(vio->mysql_socket),
                       buf, (int) size));

  if (vio->async_context && vio->async_context->active)
    ret= my_ssl_write_async(vio->async_context, vio->ssl_arg, buf,
                            size);
  else
  {
    while ((ret= ma_tls_write(sess, buf, size)) < 0)
    {
      enum enum_vio_io_event event;

      /* Process the SSL I/O error. */
      if (!ma_tls_should_retry(vio->ssl_arg, ret, &event))
        break;

      /* Attempt to wait for an I/O event. */
      if (vio_socket_io_wait(vio, event))
        break;
    }
  }

  DBUG_RETURN(ret < 0 ? -1 : ret);
}

int vio_ssl_close(Vio *vio)
{
  DBUG_ENTER("vio_ssl_close");
  ma_tls_sess_close(vio->ssl_arg);
  DBUG_RETURN(vio_close(vio));
}


void vio_ssl_delete(Vio *vio)
{
  if (!vio)
    return; /* It must be safe to delete null pointer */

  if (vio->type == VIO_TYPE_SSL)
    vio_ssl_close(vio); /* Still open, close connection first */

  if (vio->ssl_arg)
  {
    ma_tls_sess_free(vio->ssl_arg);
    vio->ssl_arg= 0;
  }

  vio_delete(vio);
}

/**
  Loop and wait until a SSL handshake is completed.

  @param vio    VIO object representing a SSL connection.
  @param sess   session structure for the tls connection.
  @param flags  flags for client or server  

  @return Return value is 1 on success.
*/

static int ssl_handshake_loop(Vio *vio, MA_TLS_SESSION sess, int flags)
{
  int ret;

  vio->ssl_arg= sess;

  /* Initiate the SSL handshake. */
  while ((ret= ma_tls_handshake(sess, flags)) < 1)
  {
    enum enum_vio_io_event event;

    /* Process the SSL I/O error. */
    if (!ma_tls_should_retry(sess, ret, &event))
      break;

    /* Wait for I/O so that the handshake can proceed. */
    if (vio_socket_io_wait(vio, event))
      break;
  }

  vio->ssl_arg= NULL;
  return ret;
}


static int ssl_do(struct st_VioSSLFd *ptr, Vio *vio, long timeout,
                  int flags, unsigned long *errptr)
{
  int r;
  MA_TLS_SESSION sess= 0;
  my_bool unused;
  my_bool was_blocking;
  my_socket sd= mysql_socket_getfd(vio->mysql_socket);
  DBUG_ENTER("ssl_do");
  DBUG_PRINT("enter", ("ptr: 0x%lx, sd: %d  ctx: 0x%lx",
                       (long) ptr, sd, (long) ptr->ssl_context));

  /* Set socket to blocking if not already set */
  vio_blocking(vio, 1, &was_blocking);

  if ((*errptr= ma_tls_sess_new(&sess, ptr->ssl_context, flags)))
  {
    DBUG_PRINT("error", ("Failed to create session object"));
    vio_blocking(vio, was_blocking, &unused);
    DBUG_RETURN(1);
  }
  DBUG_PRINT("info", ("ssl: 0x%lx timeout: %ld", (long) sess, timeout));

#if !defined(HAVE_OPENSSL)
  if (ma_tls_sess_set_cipher(sess, ptr->cipher, flags))
  {
    DBUG_PRINT("error", ("Failed to set cipher"));
    ma_tls_sess_free(sess);
    DBUG_RETURN(1);
  }
#endif

  ma_tls_set_context(sess, ptr->ssl_context);

/* ToDo: fix connect timeout in OpenSSL */
#if defined(HAVE_GNUTLS)
  if (timeout)
    gnutls_handshake_set_timeout(sess, timeout * 1000);
#endif

  if ((*errptr= ma_tls_sess_transport_set(sess, &sd, NULL, NULL)))
  {
    DBUG_PRINT("error", ("Failed to set session transport mechanism"));
    vio_blocking(vio, was_blocking, &unused);
    ma_tls_sess_free(sess);
    DBUG_RETURN(1);
  }

  if ((r= ssl_handshake_loop(vio, sess, flags)) < 1)
  {
    DBUG_PRINT("error", ("SSL handshake failure"));
    ma_tls_sess_free(sess);
    *errptr= r;
    vio_blocking(vio, was_blocking, &unused);
    DBUG_RETURN(1);
  }

  /*
    Connection succeeded. Install new function handlers,
    change type, set sd to the fd used when connecting
    and set pointer to the SSL structure
  */
  if (vio_reset(vio, VIO_TYPE_SSL, ma_tls_transport_get_int(sess), sess, 0))
  {
    vio_blocking(vio, was_blocking, &unused);
    DBUG_RETURN(1);
  }

  DBUG_RETURN(0);
}


int sslaccept(struct st_VioSSLFd *ptr, Vio *vio, long timeout, unsigned long *errptr)
{
  DBUG_ENTER("sslaccept");
  DBUG_RETURN(ssl_do(ptr, vio, timeout, MA_TLS_SERVER, errptr));
}


int sslconnect(struct st_VioSSLFd *ptr, Vio *vio, long timeout, unsigned long *errptr)
{
  DBUG_ENTER("sslconnect");
  DBUG_RETURN(ssl_do(ptr, vio, timeout, MA_TLS_CLIENT, errptr));
}


int vio_ssl_blocking(Vio *vio __attribute__((unused)),
		     my_bool set_blocking_mode,
		     my_bool *old_mode)
{
  /* Mode is always blocking */
  *old_mode= 1;
  /* Return error if we try to change to non_blocking mode */
  return (set_blocking_mode ? 0 : 1);
}

my_bool vio_ssl_has_data(Vio *vio)
{
  return ma_tls_has_data(vio->ssl_arg);
}

#endif
