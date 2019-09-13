/* tls.c
** strophe XMPP client library -- TLS abstraction header
**
** Copyright (C) 2005-2009 Collecta, Inc.
**
**  This software is provided AS-IS with no warranty, either express
**  or implied.
**
**  This program is dual licensed under the MIT and GPLv3 licenses.
*/

/** @file
 *  TLS implementation with GNUTLS
 */

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "common.h"
#include "tls.h"
#include "sock.h"

/* FIXME this shouldn't be a constant string */
#define CAFILE "/etc/ssl/certs/ca-certificates.crt"

struct _tls {
    xmpp_ctx_t *ctx; /* do we need this? */
    sock_t sock;
    gnutls_session_t session;
    gnutls_certificate_credentials_t cred;
    int lasterror;
};

void tls_initialize(void)
{
    /* initialize the GNU TLS global state */
    gnutls_global_init();

    /* TODO: wire in xmpp_ctx_t allocator somehow?
       unfortunately in gnutls it's global, so we can
       only do so much. */
}

void tls_shutdown(void)
{
    /* tear down the GNU TLS global state */
    gnutls_global_deinit();
}

tls_t *tls_new(xmpp_conn_t *conn)
{
    tls_t *tls = xmpp_alloc(conn->ctx, sizeof(tls_t));

    if (tls) {
        tls->ctx = conn->ctx;
        tls->sock = conn->sock;
        gnutls_init(&tls->session, GNUTLS_CLIENT);

        gnutls_certificate_allocate_credentials(&tls->cred);
        tls_set_credentials(tls, CAFILE);

        gnutls_set_default_priority(tls->session);

        /* fixme: this may require setting a callback on win32? */
        gnutls_transport_set_int(tls->session, conn->sock);
    }

    return tls;
}

void tls_free(tls_t *tls)
{
    gnutls_deinit(tls->session);
    gnutls_certificate_free_credentials(tls->cred);
    xmpp_free(tls->ctx, tls);
}


/* The following code is based on print_x509_certificate_info() from the gnutls examples.
 * It explicitly states"This example code is placed in the public domain."
 */
static const char *bin2hex(const void *bin, size_t bin_size)
{
        static char printable[110];
        const unsigned char *_bin = bin;
        char *print;
        size_t i;

        if (bin_size > 50)
                bin_size = 50;

        print = printable;
        for (i = 0; i < bin_size; i++) {
                sprintf(print, "%.2x ", _bin[i]);
                print += 2;
        }

        return printable;
}

static struct _tlscert_t *get_certificate_info(xmpp_ctx_t ctx, gnutls_session_t session)
{
    char buf[256];
    size_t size;
    unsigned int algo, bits;
    time_t expiration_time, activation_time;
    const gnutls_datum_t *cert_list;
    unsigned int cert_list_size = 0;
    gnutls_x509_crt_t cert;
    gnutls_datum_t cinfo;

    /* This function only works for X.509 certificates.
     */
    if (gnutls_certificate_type_get(session) != GNUTLS_CRT_X509)
        return NULL;

    cert_list = gnutls_certificate_get_peers(session, &cert_list_size);

    if (cert_list_size > 0) {
        struct _tlscert_t *tlscert = xmpp_alloc(ctx, sizeof(*tlscert));
        memset(tlscert, 0, sizeof(*tlscert));

        /* we only print information about the first certificate.
         */
        if(gnutls_x509_crt_init(&cert)) goto LBL_ERR;

        if(gnutls_x509_crt_import(cert, &cert_list[0], GNUTLS_X509_FMT_DER)) goto LBL_ERR;

        /* If you want to extract fields manually for some other reason,
         below are popular example calls. */

        expiration_time = gnutls_x509_crt_get_expiration_time(cert);
        activation_time = gnutls_x509_crt_get_activation_time(cert);

        tlscert->notbefore = strdup(ctime(&activation_time));
        tlscert->notafter = strdup(ctime(&expiration_time));

        /* Print the serial number of the certificate.
         */
        size = sizeof(buf);
        if(gnutls_x509_crt_get_serial(cert, buf, &size)) goto LBL_ERR;

        tlscert->serialnumber = strdup(bin2hex(buf, size));

        /* Extract some of the public key algorithm's parameters
         */
        algo = gnutls_x509_crt_get_pk_algorithm(cert, &bits);

        tlscert->keyalg = strdup(gnutls_pk_algorithm_get_name(algo));

        /* Get the version of the X.509
         * certificate.
         */
        tlscert->version = gnutls_x509_crt_get_version(cert);

        size = sizeof(buf);
        if(gnutls_x509_crt_get_dn(cert, buf, &size)) goto LBL_ERR;
        tlscert->subjectname = strdup(buf);

        size = sizeof(buf);
        if(gnutls_x509_crt_get_issuer_dn(cert, buf, &size)) goto LBL_ERR;
        tlscert->issuername = strdup(buf);

        size = sizeof(buf);
        if(gnutls_x509_crt_get_fingerprint(cert, GNUTLS_DIG_SHA1, buf, &size)) goto LBL_ERR;
        tlscert->fingerprint = strdup(buf);

        tlscert->sigalg = strdup(gnutls_sign_get_name(gnutls_x509_crt_get_signature_algorithm(cert)));

        gnutls_x509_crt_deinit(cert);
        return tlscert;
LBL_ERR:
        xmpp_conn_free_tlscert(tlscert);
    }
    return NULL;
}

xmpp_tlscert_t *tls_peer_cert(xmpp_conn_t *conn)
{
    if (conn && conn->tls && conn->tls->session) {
        return get_certificate_info(conn->ctx, conn->tls->session);
    } else {
        return NULL;
    }
}

int tls_set_credentials(tls_t *tls, const char *cafilename)
{
    int err;

    /* set trusted credentials -- takes a .pem filename */
    err = gnutls_certificate_set_x509_trust_file(tls->cred,
            cafilename, GNUTLS_X509_FMT_PEM);
    if (err >= 0) {
        err = gnutls_credentials_set(tls->session, GNUTLS_CRD_CERTIFICATE,
                                     tls->cred);
    }
    tls->lasterror = err;

    return err == GNUTLS_E_SUCCESS;
}

int tls_start(tls_t *tls)
{
    sock_set_blocking(tls->sock);
    tls->lasterror = gnutls_handshake(tls->session);
    sock_set_nonblocking(tls->sock);

    return tls->lasterror == GNUTLS_E_SUCCESS;
}

int tls_stop(tls_t *tls)
{
    tls->lasterror = gnutls_bye(tls->session, GNUTLS_SHUT_RDWR);
    return tls->lasterror == GNUTLS_E_SUCCESS;
}

int tls_error(tls_t *tls)
{
    return tls->lasterror;
}

int tls_is_recoverable(int error)
{
    return !gnutls_error_is_fatal(error);
}

int tls_pending(tls_t *tls)
{
    return gnutls_record_check_pending (tls->session);
}

int tls_read(tls_t *tls, void * const buff, const size_t len)
{
    int ret;

    ret = gnutls_record_recv(tls->session, buff, len);
    tls->lasterror = ret < 0 ? ret : 0;

    return ret;
}

int tls_write(tls_t *tls, const void * const buff, const size_t len)
{
    int ret;

    ret = gnutls_record_send(tls->session, buff, len);
    tls->lasterror = ret < 0 ? ret : 0;

    return ret;
}

int tls_clear_pending_write(tls_t *tls)
{
    return 0;
}
