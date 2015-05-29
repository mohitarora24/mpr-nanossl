/*
    nanossl.c - Mocana NanoSSL

    This is the interface between the MPR Socket layer and the NanoSSL stack.

    This software is supplied as-is. It is not supported under an Embedthis Commerical License or
    Appweb Maintenance Agreement.

    At a minimum, the following should be defined in NanoSSL src/common/moptions_custom.h

    #define __ENABLE_MOCANA_SSL_SERVER__                1
    #define __ENABLE_MOCANA_PEM_CONVERSION__            1
    #define __MOCANA_DUMP_CONSOLE_TO_STDOUT__           1
    #define __ENABLE_MOCANA_SSL_CIPHER_SUITES_SELECT__  1

    #if ME_DEBUG
    #define __ENABLE_ALL_DEBUGGING__                    1
    #define __ENABLE_MOCANA_DEBUG_CONSOLE__             1
    #endif

    Notes:
    - NanoSSL does not support virtual servers or multiple configurations
    - NanoSSL sometimes returns invalid ASN.1 to clients
    - This module does not support client certification or verification of client certificates

    Copyright (c) All Rights Reserved. See details at the end of the file.
 */

/********************************** Includes **********************************/

#include    "me.h"

#if ME_COM_NANOSSL
#if WINDOWS
    #define __RTOS_WIN32__
#elif MACOSX
    #define __RTOS_OSX__
#elif VXWORKS
    #define __RTOS_VXWORKS__
#else
    #define __RTOS_LINUX__
#endif

#include  "mpr.h"

/*
    Indent includes to bypass MakeMe dependencies
 */
 #include "common/moptions.h"
 #include "common/mdefs.h"
 #include "common/mtypes.h"
 #include "common/merrors.h"
 #include "common/mrtos.h"
 #include "common/mtcp.h"
 #include "common/mocana.h"
 #include "common/random.h"
 #include "common/vlong.h"
 #include "crypto/hw_accel.h"
 #include "crypto/crypto.h"
 #include "crypto/pubcrypto.h"
 #include "crypto/ca_mgmt.h"
 #include "ssl/ssl.h"
 #include "asn1/oiddefs.h"

/************************************* Defines ********************************/

#define KEY_SIZE        1024
#define MAX_CIPHERS     32

/*
    Per-route SSL configuration
 */
typedef struct NanoConfig {
    certDescriptor  cert;
    certDescriptor  ca;
    ubyte2          ciphers[MAX_CIPHERS];
    int             ciphersCount;
} NanoConfig;

/*
    Per socket state
 */
typedef struct NanoSocket {
    MprSocket       *sock;
    NanoConfig      *cfg;
    sbyte4          handle;
    int             connected;
} NanoSocket;

static MprSocketProvider *nanoProvider;
static NanoConfig *nanoConfig;

#if ME_DEBUG
    #define SSL_HELLO_TIMEOUT   15000000
    #define SSL_RECV_TIMEOUT    30000000
#else
    #define SSL_HELLO_TIMEOUT   15000
    #define SSL_RECV_TIMEOUT    300000
#endif

/***************************** Forward Declarations ***************************/

static void     nanoClose(MprSocket *sp, bool gracefully);
static void     nanoDisconnect(MprSocket *sp);
static void     nanoLog(sbyte4 module, sbyte4 severity, sbyte *msg);
static void     manageNanoConfig(NanoConfig *cfg, int flags);
static void     manageNanoProvider(MprSocketProvider *provider, int flags);
static void     manageNanoSocket(NanoSocket *ssp, int flags);
static ssize    nanoRead(MprSocket *sp, void *buf, ssize len);
static int      computeNanoCiphers(MprSsl *ssl);
static int      nanoUpgrade(MprSocket *sp, MprSsl *sslConfig, cchar *peerName);
static ssize    nanoWrite(MprSocket *sp, cvoid *buf, ssize len);

/************************************* Code ***********************************/
/*
    Create the NanoSSL module. This is called only once.
 */
PUBLIC int mprSslInit(void *unused, MprModule *module)
{
    sslSettings     *settings;

    if ((nanoProvider = mprAllocObj(MprSocketProvider, manageNanoProvider)) == NULL) {
        return MPR_ERR_MEMORY;
    }
    nanoProvider->upgradeSocket = nanoUpgrade;
    nanoProvider->closeSocket = nanoClose;
    nanoProvider->disconnectSocket = nanoDisconnect;
    nanoProvider->readSocket = nanoRead;
    nanoProvider->writeSocket = nanoWrite;
    mprAddSocketProvider("nanossl", nanoProvider);

    if (MOCANA_initMocana() < 0) {
        mprLog("error nanossl", 0, "initialization failed");
        return MPR_ERR_CANT_INITIALIZE;
    }
    MOCANA_initLog(nanoLog);
    if (SSL_init(SOMAXCONN, 0) < 0) {
        mprLog("error nanossl", 0, "SSL_init failed");
        return MPR_ERR_CANT_INITIALIZE;
    }
    settings = SSL_sslSettings();
    settings->sslTimeOutHello = SSL_HELLO_TIMEOUT;
    settings->sslTimeOutReceive = SSL_RECV_TIMEOUT;
    return 0;
}


static void manageNanoProvider(MprSocketProvider *provider, int flags)
{
    if (flags & MPR_MANAGE_MARK) {
        mprMark(provider->name);

    } else if (flags & MPR_MANAGE_FREE) {
        SSL_releaseTables();
        MOCANA_freeMocana();
    }
}


static void manageNanoConfig(NanoConfig *cfg, int flags)
{
    if (flags & MPR_MANAGE_MARK) {
        ;
    } else if (flags & MPR_MANAGE_FREE) {
        if (cfg->cert.certLength > 0) {
            CA_MGMT_freeCertificate(&cfg->cert);
            cfg->cert.certLength = 0;
        }
        if (cfg->ca.certLength > 0) {
            CA_MGMT_freeCertificate(&cfg->ca);
            cfg->ca.certLength = 0;
        }
    }
}


static void manageNanoSocket(NanoSocket *np, int flags)
{
    if (flags & MPR_MANAGE_MARK) {
        mprMark(np->cfg);
        mprMark(np->sock);

    } else if (flags & MPR_MANAGE_FREE) {
        if (np->handle) {
            SSL_closeConnection(np->handle);
            np->handle = 0;
        }
    }
}


static void nanoClose(MprSocket *sp, bool gracefully)
{
    NanoSocket      *np;

    np = sp->sslSocket;
    lock(sp);
    sp->service->standardProvider->closeSocket(sp, gracefully);
    if (np->handle) {
        SSL_closeConnection(np->handle);
        np->handle = 0;
    }
    unlock(sp);
}


/*
    Upgrade a standard socket to use TLS
 */
static int nanoUpgrade(MprSocket *sp, MprSsl *ssl, cchar *peerName)
{
    NanoSocket  *np;
    NanoConfig  *cfg;
    int         rc;
    ubyte4      ecurves;

    assert(sp);

    if (ssl == 0) {
        ssl = mprCreateSsl(sp->flags & MPR_SOCKET_SERVER);
    }
    if ((np = (NanoSocket*) mprAllocObj(NanoSocket, manageNanoSocket)) == 0) {
        return MPR_ERR_MEMORY;
    }
    np->sock = sp;
    sp->sslSocket = np;
    sp->ssl = ssl;

    lock(ssl);
    if (ssl->config) {
        np->cfg = cfg = ssl->config;

    } else if (nanoConfig) {
        np->cfg = cfg = ssl->config = nanoConfig;

    } else {
        /*
            One time setup for the SSL configuration
         */
        if ((cfg = mprAllocObj(NanoConfig, manageNanoConfig)) == 0) {
            unlock(ssl);
            return MPR_ERR_MEMORY;
        }
        if (ssl->certFile) {
            certDescriptor tmp;
            if ((rc = MOCANA_readFile((sbyte*) ssl->certFile, &tmp.pCertificate, &tmp.certLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to read certificate %s", ssl->certFile); 
                CA_MGMT_freeCertificate(&tmp);
                unlock(ssl);
                return MPR_ERR_CANT_READ;
            }
            if ((rc = CA_MGMT_decodeCertificate(tmp.pCertificate, tmp.certLength, &cfg->cert.pCertificate, 
                    &cfg->cert.certLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to decode PEM certificate %s", ssl->certFile); 
                CA_MGMT_freeCertificate(&tmp);
                unlock(ssl);
                return MPR_ERR_CANT_READ;
            }
            MOCANA_freeReadFile(&tmp.pCertificate);
        }
        if (ssl->keyFile) {
            certDescriptor tmp;
            if ((rc = MOCANA_readFile((sbyte*) ssl->keyFile, &tmp.pKeyBlob, &tmp.keyBlobLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to read key file %s", ssl->keyFile); 
                CA_MGMT_freeCertificate(&cfg->cert);
                unlock(ssl);
            }
            if ((rc = CA_MGMT_convertKeyPEM(tmp.pKeyBlob, tmp.keyBlobLength, &cfg->cert.pKeyBlob, 
                    &cfg->cert.keyBlobLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to decode PEM key file %s", ssl->keyFile); 
                CA_MGMT_freeCertificate(&tmp);
                unlock(ssl);
                return MPR_ERR_CANT_READ;
            }
            MOCANA_freeReadFile(&tmp.pKeyBlob);    
        }
        if (ssl->caFile) {
            certDescriptor tmp;
            if ((rc = MOCANA_readFile((sbyte*) ssl->caFile, &tmp.pCertificate, &tmp.certLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to read CA certificate file %s", ssl->caFile); 
                CA_MGMT_freeCertificate(&tmp);
                unlock(ssl);
                return MPR_ERR_CANT_READ;
            }
            if ((rc = CA_MGMT_decodeCertificate(tmp.pCertificate, tmp.certLength, &cfg->ca.pCertificate, 
                    &cfg->ca.certLength)) < 0) {
                mprLog("error nanossl", 0, "Unable to decode PEM certificate %s", ssl->caFile); 
                CA_MGMT_freeCertificate(&tmp);
                unlock(ssl);
                return MPR_ERR_CANT_READ;
            }
            MOCANA_freeReadFile(&tmp.pCertificate);
        }
        ecurves = 1 << tlsExtNamedCurves_secp256r1;
        if (SSL_initServerCert(&cfg->cert, FALSE, ecurves)) {
            mprLog("error nanossl", 0, "SSL_initServerCert failed");
            unlock(ssl);
            return MPR_ERR_CANT_INITIALIZE;
        }
        nanoConfig = np->cfg = ssl->config = cfg;

        if (computeNanoCiphers(ssl) < 0) {
            unlock(ssl);
            return MPR_ERR_CANT_INITIALIZE;
        }
    }
    unlock(ssl);

    if (sp->flags & MPR_SOCKET_SERVER) {
        if ((np->handle = SSL_acceptConnection(sp->fd)) < 0) {
            return -1;
        }
    }
    return 0;
}


static void nanoDisconnect(MprSocket *sp)
{
    sp->service->standardProvider->disconnectSocket(sp);
}


/*
    Initiate or continue SSL handshaking with the peer. This routine does not block.
    Return -1 on errors, 0 incomplete and awaiting I/O, 1 if successful
*/
static int nanoHandshake(MprSocket *sp)
{
    NanoSocket  *np;
    NanoConfig  *cfg;
    ubyte4      ecurve;
    ubyte2      cipher;
    int         rc;

    np = (NanoSocket*) sp->sslSocket;
    cfg = np->cfg;
    sp->flags |= MPR_SOCKET_HANDSHAKING;

    if (cfg->ciphersCount > 0) {
        if (SSL_enableCiphers(np->handle, cfg->ciphers, cfg->ciphersCount) < 0) {
            mprLog("error nanossl", 0, "Requested cipher suite %s is not supported by this provider", sp->ssl->ciphers);
            return MPR_ERR_BAD_STATE;
        }
    }
    rc = 0;
    while (!np->connected) {
        if ((rc = SSL_negotiateConnection(np->handle)) < 0) {
            break;
        }
        np->connected = 1;
        sp->secured = 1;
        break;
    }
    sp->flags &= ~MPR_SOCKET_HANDSHAKING;

    /*
        Analyze the handshake result
    */
    if (rc < 0) {
        if (rc == ERR_SSL_UNKNOWN_CERTIFICATE_AUTHORITY) {
            sp->errorMsg = sclone("Unknown certificate authority");
        } else if (rc == ERR_SSL_NO_CIPHER_MATCH) {
            sp->errorMsg = sclone("No cipher match");
        } else if (rc == ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE) {
            sp->errorMsg = sclone("Bad certificate");
        } else if (rc == ERR_SSL_NO_SELF_SIGNED_CERTIFICATES) {
            sp->errorMsg = sclone("Self-signed certificate");
        } else if (rc == ERR_SSL_CERT_VALIDATION_FAILED) {
            sp->errorMsg = sclone("Certificate does not validate");
        } else if (rc == ERR_TCP_SOCKET_CLOSED) {
            sp->errorMsg = sclone("Peer closed connection");
        } else {
            sp->errorMsg = sclone("NanoSSL error");
        }
        mprLog("error mpr ssl nanossl", 4, "Cannot handshake: %s, error %d", sp->errorMsg, rc);
        errno = EPROTO;
        sp->flags |= MPR_SOCKET_EOF;
        return -1;
    }
    if (SSL_getCipherInfo(np->handle, &cipher, &ecurve) < 0) {
        mprLog("error mpr ssl nanossl", 0, "Cannot get cipher info");
        sp->flags |= MPR_SOCKET_EOF;
        return -1;
    }
    sp->cipher = sclone(mprGetSslCipherName(cipher));
    return 1;
}


/*
    Return the number of bytes read. Return -1 on errors and EOF. Distinguish EOF via mprIsSocketEof
 */
static ssize nanoRead(MprSocket *sp, void *buf, ssize len)
{
    NanoSocket  *np;
    sbyte4      nbytes, count;
    int         rc;

    np = (NanoSocket*) sp->sslSocket;
    assert(np);
    assert(np->cfg);

    if (sp->fd == INVALID_SOCKET) {
        return -1;
    }
    if (!np->connected && (rc = nanoHandshake(sp)) <= 0) {
        return rc;
    }
    while (1) {
        nbytes = 0;
        rc = SSL_recv(np->handle, buf, (sbyte4) len, &nbytes, 0);
        mprLog("info mpr ssl nanossl", 5, "ssl_read %d", rc);
        if (rc < 0) {
            if (rc != ERR_TCP_READ_ERROR) {
                sp->flags |= MPR_SOCKET_EOF;
            }
            nbytes = -1;
        }
        break;
    }
    SSL_recvPending(np->handle, &count);
    mprHiddenSocketData(sp, count, MPR_READABLE);
    return nbytes;
}


/*
    Write data. Return the number of bytes written or -1 on errors.
 */
static ssize nanoWrite(MprSocket *sp, cvoid *buf, ssize len)
{
    NanoSocket  *np;
    ssize       totalWritten;
    int         rc, count, sent;

    np = (NanoSocket*) sp->sslSocket;
    if (len <= 0) {
        assert(0);
        return -1;
    }
    if (!np->connected && (rc = nanoHandshake(sp)) <= 0) {
        return rc;
    }
    totalWritten = 0;
    rc = 0;
    do {
        rc = sent = SSL_send(np->handle, (sbyte*) buf, (int) len);
        mprLog("info mpr ssl nanossl", 5, "written %d, requested len %ld", sent, len);
        if (rc <= 0) {
            break;
        }
        totalWritten += sent;
        buf = (void*) ((char*) buf + sent);
        len -= sent;
        mprLog("info mpr ssl nanossl", 5, "write: len %ld, written %d, total %ld", len, sent, totalWritten);
    } while (len > 0);

    SSL_sendPending(np->handle, &count);
    mprHiddenSocketData(sp, count, MPR_WRITABLE);
    if (totalWritten == 0 && rc < 0 && errno == EAGAIN) {
        return -1;
    }
    return totalWritten;
}


static int computeNanoCiphers(MprSsl *ssl)
{
    NanoConfig  *cfg;
    char        *suite, *cipher, *next;
    int         count, cipherCode;

    if (ssl->ciphers) {
        cfg = ssl->config;
        mprLog("info openssl", 5, "Using SSL ciphers: %s", ssl->ciphers);
        next = sclone(ssl->ciphers);
        count = 0;
        while ((cipher = stok(next, ":, \t", &next)) != 0 && count < MAX_CIPHERS) {
            if ((cipherCode = mprGetSslCipherCode(cipher)) < 0) {
                mprLog("error nanossl", 0, "Unknown cipher %s", cipher);
            } else {
                cfg->ciphers[count++] = cipherCode;
            }
            suite = 0;
        }
        cfg->ciphersCount = count;
    }
    return 0;
}


static void nanoLog(sbyte4 module, sbyte4 severity, sbyte *msg)
{
    mprLog("mpr ssl nanossl", 3, "%s", (cchar*) msg);
}

#endif /* ME_COM_NANOSSL */

/*
    @copy   default

    Copyright (c) Embedthis Software. All Rights Reserved.

    This software is distributed under commercial and open source licenses.
    You may use the Embedthis Open Source license or you may acquire a 
    commercial license from Embedthis Software. You agree to be fully bound
    by the terms of either license. Consult the LICENSE.md distributed with
    this software for full details and other copyrights.

    Local variables:
    tab-width: 4
    c-basic-offset: 4
    End:
    vim: sw=4 ts=4 expandtab

    @end
 */
