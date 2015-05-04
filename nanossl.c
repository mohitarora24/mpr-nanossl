/*
    nanossl.c - Mocana NanoSSL

    Copyright (c) All Rights Reserved. See details at the end of the file.

    WARNING: This code has not been updated and may or may not work.
 */

/********************************** Includes **********************************/

#include    "mpr.h"

#if WINDOWS
    #define __RTOS_WIN32__
#elif MACOSX
    #define __RTOS_OSX__
#elif VXWORKS
    #define __RTOS_VXWORKS__
#else
    #define __RTOS_LINUX__
#endif

#define __ENABLE_MOCANA_SSL_SERVER__        1
#define __ENABLE_MOCANA_PEM_CONVERSION__    1
#define __ENABLE_ALL_DEBUGGING__            1
#define __ENABLE_MOCANA_DEBUG_CONSOLE__     1
#define __MOCANA_DUMP_CONSOLE_TO_STDOUT__   1

/*
    Indent includes to bypass MakeMe dependencies
 */
#if ME_COM_NANOSSL
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
/*
    Per-route SSL configuration
 */
typedef struct NanoConfig {
    certDescriptor  cert;
    certDescriptor  ca;
} NanoConfig;

/*
    Per socket state
 */
typedef struct NanoSocket {
    MprSocket       *sock;
    NanoConfig       *cfg;
    sbyte4          handle;
    int             connected;
} NanoSocket;

static MprSocketProvider *nanoProvider;
static NanoConfig *defaultNanoConfig;

#if ME_DEBUG
    #define SSL_HELLO_TIMEOUT   15000
    #define SSL_RECV_TIMEOUT    300000
#else
    #define SSL_HELLO_TIMEOUT   15000000
    #define SSL_RECV_TIMEOUT    30000000
#endif

#define KEY_SIZE                1024
#define MAX_CIPHERS             16

/***************************** Forward Declarations ***************************/

static void     nanoClose(MprSocket *sp, bool gracefully);
static void     nanoDisconnect(MprSocket *sp);
static Socket   nanoListen(MprSocket *sp, cchar *host, int port, int flags);
static void     nanoLog(sbyte4 module, sbyte4 severity, sbyte *msg);
static void     manageNanoConfig(NanoConfig *cfg, int flags);
static void     manageNanoProvider(MprSocketProvider *provider, int flags);
static void     manageNanoSocket(NanoSocket *ssp, int flags);
static ssize    nanoRead(MprSocket *sp, void *buf, ssize len);
static int      setNanoCiphers(MprSocket *sp, cchar *cipherSuite);
static int      nanoUpgrade(MprSocket *sp, MprSsl *sslConfig, cchar *peerName);
static ssize    nanoWrite(MprSocket *sp, cvoid *buf, ssize len);

static void     DEBUG_PRINT(void *where, void *msg);
static void     DEBUG_PRINTNL(void *where, void *msg);

/************************************* Code ***********************************/
/*
    Create the Openssl module. This is called only once
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

    if ((defaultNanoConfig = mprAllocObj(NanoConfig, manageNanoConfig)) == 0) {
        return MPR_ERR_MEMORY;
    }
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
        mprMark(defaultNanoConfig);

    } else if (flags & MPR_MANAGE_FREE) {
        defaultNanoConfig = 0;
        SSL_releaseTables();
        MOCANA_freeMocana();
    }
}


static void manageNanoConfig(NanoConfig *cfg, int flags)
{
    if (flags & MPR_MANAGE_MARK) {
        ;
    } else if (flags & MPR_MANAGE_FREE) {
        CA_MGMT_freeCertificate(&cfg->cert);
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
    NanoSocket   *np;
    NanoConfig   *cfg;
    int         rc;

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
    if (ssl->config && !ssl->changed) {
        np->cfg = cfg = ssl->config;
    } else {
        ssl->changed = 0;
        /*
            One time setup for the SSL configuration for this MprSsl
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
            assert(__ENABLE_MOCANA_PEM_CONVERSION__);
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
            if ((rc = CA_MGMT_convertKeyPEM(tmp.pKeyBlob, tmp.keyBlobLength, 
                    &cfg->cert.pKeyBlob, &cfg->cert.keyBlobLength)) < 0) {
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
        if (SSL_initServerCert(&cfg->cert, FALSE, 0)) {
            mprLog("error nanossl", 0, "SSL_initServerCert failed");
            unlock(ssl);
            return MPR_ERR_CANT_INITIALIZE;
        }
        np->cfg = ssl->config = cfg;
    }
    unlock(ssl);

    if (sp->flags & MPR_SOCKET_SERVER) {
        if ((np->handle = SSL_acceptConnection(sp->fd)) < 0) {
            return -1;
        }
    } else {
        mprLog("error nanossl", 0, "does not support client side SSL");
    }
    return 0;
}


static void nanoDisconnect(MprSocket *sp)
{
    sp->service->standardProvider->disconnectSocket(sp);
}


static void checkCert(MprSocket *sp)
{
    NanoSocket  *np;
    MprCipher   *cp;
    MprSsl      *ssl;
    ubyte2      cipher;
    ubyte4      ecurve;
   
    ssl = sp->ssl;
    np = (NanoSocket*) sp->sslSocket;

    if (ssl->caFile) {
        mprLog("info mpr ssl nanossl", 4, "Using certificates from %s", ssl->caFile);
    } else if (ssl->caPath) {
        mprLog("info mpr ssl nanossl", 4, "Using certificates from directory %s", ssl->caPath);
    }
    /*
        Trace cipher being used
     */
    if (SSL_getCipherInfo(np->handle, &cipher, &ecurve) < 0) {
        mprLog("error mpr ssl nanossl", 0, "Cannot get cipher info");
        return;
    }
    for (cp = mprCiphers; cp->name; cp++) {
        if (cp->code == cipher) {
            break;
        }
    }
    if (cp) {
        mprLog("info mpr ssl nanossl", 0, "Connected using cipher: %s, %x", cp->name, (int) cipher);
    } else {
        mprLog("info mpr ssl nanossl", 0, "Connected using cipher: %x", (int) cipher);
    }
}


/*
    Initiate or continue SSL handshaking with the peer. This routine does not block.
    Return -1 on errors, 0 incomplete and awaiting I/O, 1 if successful
*/
static int nanoHandshake(MprSocket *sp)
{
    NanoSocket  *np;
    ubyte4      flags;
    int         rc;

    np = (NanoSocket*) sp->sslSocket;
    sp->flags |= MPR_SOCKET_HANDSHAKING;
    if (setNanoCiphers(sp, sp->ssl->ciphers) < 0) {
        return 0;
    }
    SSL_getSessionFlags(np->handle, &flags);
    if (sp->ssl->verifyPeer) {
        flags |= SSL_FLAG_REQUIRE_MUTUAL_AUTH;
    } else {
        flags |= SSL_FLAG_NO_MUTUAL_AUTH_REQUEST;
    }
    SSL_setSessionFlags(np->handle, flags);
    rc = 0;

    while (!np->connected) {
        if ((rc = SSL_negotiateConnection(np->handle)) < 0) {
            break;
        }
        np->connected = 1;
        break;
    }
    sp->flags &= ~MPR_SOCKET_HANDSHAKING;

    /*
        Analyze the handshake result
    */
    if (rc < 0) {
        if (rc == ERR_SSL_UNKNOWN_CERTIFICATE_AUTHORITY) {
            sp->errorMsg = sclone("Unknown certificate authority");

        /* Common name mismatch, cert revoked */
        } else if (rc == ERR_SSL_PROTOCOL_PROCESS_CERTIFICATE) {
            sp->errorMsg = sclone("Bad certificate");
        } else if (rc == ERR_SSL_NO_SELF_SIGNED_CERTIFICATES) {
            sp->errorMsg = sclone("Self-signed certificate");
        } else if (rc == ERR_SSL_CERT_VALIDATION_FAILED) {
            sp->errorMsg = sclone("Certificate does not validate");
        }
        DISPLAY_ERROR(0, rc); 
        mprLog("error mpr ssl nanossl", 4, "Cannot handshake: error %d", rc);
        errno = EPROTO;
        return -1;
    }
    checkCert(sp);
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
        mprLog("info mpr ssl nanossl", 5, "written %d, requested len %d", sent, len);
        if (rc <= 0) {
            break;
        }
        totalWritten += sent;
        buf = (void*) ((char*) buf + sent);
        len -= sent;
        mprLog("info mpr ssl nanossl", 5, "write: len %d, written %d, total %d", len, sent, totalWritten);
    } while (len > 0);

    SSL_sendPending(np->handle, &count);
    mprHiddenSocketData(sp, count, MPR_WRITABLE);
    if (totalWritten == 0 && rc < 0 && errno == EAGAIN) {
        return -1;
    }
    return totalWritten;
}


static int setNanoCiphers(MprSocket *sp, cchar *cipherSuite)
{
    NanoSocket  *np;
    char        *suite, *cipher, *next;
    ubyte2      *ciphers;
    int         count, cipherCode;


    np = sp->sslSocket;
    ciphers = mprAlloc((MAX_CIPHERS + 1) * sizeof(ubyte2));

    if (!cipherSuite || cipherSuite[0] == '\0') {
        return 0;
    }
    suite = strdup(cipherSuite);
    count = 0;
    while ((cipher = stok(suite, ":, \t", &next)) != 0 && count < MAX_CIPHERS) {
        if ((cipherCode = mprGetSslCipherCode(cipher)) < 0) {
            mprLog("error nanossl", 0, "Requested cipher %s is not supported by this provider", cipher);
        } else {
            ciphers[count++] = cipherCode;
        }
        suite = 0;
    }
    if (SSL_enableCiphers(np->handle, ciphers, count) < 0) {
        mprLog("error nanossl", 0, "Requested cipher suite %s is not supported by this provider", cipherSuite);
        return MPR_ERR_BAD_STATE;
    }
    return 0;
}


static void DEBUG_PRINT(void *where, void *msg)
{
    mprLog("mpr ssl nanossl", 4, "%s", msg);
}

static void DEBUG_PRINTNL(void *where, void *msg)
{
    mprLog("mpr ssl nanossl", 4, "%s", msg);
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
