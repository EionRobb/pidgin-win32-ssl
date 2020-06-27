
// Purple includes
#include "internal.h"
#include "debug.h"
#include "sslconn.h"
#include "version.h"
#include "plugin.h"
#include "certificate.h"

#define SSL_WIN32_PLUGIN_ID "ssl-win32"

// Windows includes
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS
#include <wincrypt.h>
#include <tchar.h>
#define SECURITY_WIN32
#include <security.h>
#include <schnlsp.h>

#ifndef SP_PROT_SSL2_CLIENT
#define SP_PROT_SSL2_CLIENT             0x00000008
#endif

#ifndef SP_PROT_SSL3_CLIENT
#define SP_PROT_SSL3_CLIENT             0x00000008
#endif

#ifndef SP_PROT_TLS1_CLIENT
#define SP_PROT_TLS1_CLIENT             0x00000080
#endif

#ifndef SP_PROT_TLS1_0_CLIENT
#define SP_PROT_TLS1_0_CLIENT           SP_PROT_TLS1_CLIENT
#endif

#ifndef SP_PROT_TLS1_1_CLIENT
#define SP_PROT_TLS1_1_CLIENT           0x00000200
#endif

#ifndef SP_PROT_TLS1_2_CLIENT
#define SP_PROT_TLS1_2_CLIENT           0x00000800
#endif


#define HANDSHAKE_BUFFER_SIZE (16 * 1024)

typedef struct
{
	CtxtHandle context;
	CredHandle credentials;
	
	SecPkgContext_StreamSizes Sizes;
	
	/* Received, decrypted data */
	guchar *decrypted;
	size_t decrypted_len;
	size_t decrypted_offset;
	
	/* Received, unencrypted data */
	guchar *extra;
	size_t extra_len;
	size_t max_extra;
	
	guint handshake_handler;
} PurpleSslWin32Data;

#define PURPLE_SSL_WIN32_DATA(gsc) ((PurpleSslWin32Data *)gsc->private_data)

/** Helper macro to retrieve the PCCERT_CONTEXT certdata from a PurpleCertificate */
#define X509_WIN32_DATA(pcrt) ( (PCCERT_CONTEXT) (pcrt->data) )

static PurpleCertificateScheme x509_win32;

static void
ssl_win32_init_ssl(void)
{
	InitSecurityInterfaceA();
}

/*
static int
recv_all(int fd, const void *buf, size_t len, int flags)
{
	int rs = 0;
	while(rs < len)
	{
		int rval = recv(fd, buf + rs, len - rs, flags);
		if (rval == 0 || rval == SOCKET_ERROR)
			break;

		rs += rval;
	}
	return rs;
}*/

static int
send_all(int fd, const guchar *buf, size_t len, int flags)
{
	int rs = 0;
	while(rs < len)
	{
		int rval = send(fd, buf + rs, len - rs, flags);
		if (rval == 0 || rval == SOCKET_ERROR)
			break;

		rs += rval;
	}
	return rs;
}

static gboolean
ssl_win32_init(void)
{
   return TRUE;
}

static void
ssl_win32_uninit(void)
{
	
}


static void
ssl_win32_verified_cb(PurpleCertificateVerificationStatus st, gpointer userdata)
{
	PurpleSslConnection *gsc = (PurpleSslConnection *) userdata;

	if (st == PURPLE_CERTIFICATE_VALID) {
		/// Certificate valid? Good! Do the connection!
		gsc->connect_cb(gsc->connect_cb_data, gsc, PURPLE_INPUT_READ);
	} else {
		/// Otherwise, signal an error
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CERTIFICATE_INVALID, gsc->connect_cb_data);
		purple_ssl_close(gsc);
	}
}

static void
ssl_win32_handshake_cb(gpointer data, int fd, PurpleInputCondition cond)
{
	PurpleSslConnection *gsc = (PurpleSslConnection *)data;
	PurpleSslWin32Data *win32_data = PURPLE_SSL_WIN32_DATA(gsc);
	
	SECURITY_STATUS ss;
	
	DWORD isc_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
	                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
					  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
					  ISC_REQ_INTEGRITY;
	DWORD isc_out_flags;
	
	SecBuffer InBuffers[2];
	SecBufferDesc InBuffer;
	SecBuffer OutBuffers[1];
	SecBufferDesc OutBuffer;
	
	int err;
	
	if (gsc->verifier) {
		isc_flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
	}
	
	//purple_debug_info(SSL_WIN32_PLUGIN_ID, "ssl_win32_handshake_cb\n");
	
	//Loop over recv() and handshake
	err = wpurple_recv(fd, win32_data->extra + win32_data->extra_len, win32_data->max_extra - win32_data->extra_len, 0);
	if (err <= 0) {
		if (errno != EAGAIN) {
			gchar *err_str = g_win32_error_message(errno);
			purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error reading handshake '%s' (%d)\n", err_str, errno);
			g_free(err_str);
			
			if(gsc->error_cb != NULL)
				gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
					gsc->connect_cb_data);

			purple_ssl_close(gsc);
		}
		return;
	}
	win32_data->extra_len += err;
	
	do 
	{
		
		// Input buffers
		InBuffers[0].pvBuffer   = win32_data->extra;
		InBuffers[0].cbBuffer   = win32_data->extra_len;
		InBuffers[0].BufferType = SECBUFFER_TOKEN;

		InBuffers[1].pvBuffer   = NULL;
		InBuffers[1].cbBuffer   = 0;
		InBuffers[1].BufferType = SECBUFFER_EMPTY;

		InBuffer.cBuffers       = 2;
		InBuffer.pBuffers       = InBuffers;
		InBuffer.ulVersion      = SECBUFFER_VERSION;
		
		// Output buffers
		OutBuffers[0].pvBuffer  = NULL;
		OutBuffers[0].cbBuffer  = 0;
		OutBuffers[0].BufferType= SECBUFFER_TOKEN;

		OutBuffer.cBuffers      = 1;
		OutBuffer.pBuffers      = OutBuffers;
		OutBuffer.ulVersion     = SECBUFFER_VERSION;
	
		ss = InitializeSecurityContextA(&win32_data->credentials, &win32_data->context, NULL, isc_flags, 0, 0, &InBuffer, 0, NULL, &OutBuffer, &isc_out_flags, 0);
		
		if(ss == SEC_E_OK || ss == SEC_I_CONTINUE_NEEDED || (isc_out_flags & ISC_RET_EXTENDED_ERROR))
		{
			if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
			{
				int sent = send_all(gsc->fd, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
				//check error
				if (sent < 0) {
					if(gsc->error_cb != NULL)
						gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
							gsc->connect_cb_data);

					purple_ssl_close(gsc);
					return;
				}
			}
		}
		
		if (OutBuffers[0].pvBuffer != NULL) {
			FreeContextBuffer(OutBuffers[0].pvBuffer);
			OutBuffers[0].pvBuffer = NULL;
		}
		
		if (InBuffers[1].BufferType == SECBUFFER_EXTRA && InBuffers[1].pvBuffer != NULL && InBuffers[1].cbBuffer > 0)
		{
			g_memmove(win32_data->extra, InBuffers[1].pvBuffer, InBuffers[1].cbBuffer);
			win32_data->extra_len = InBuffers[1].cbBuffer;
		} else {
			win32_data->extra_len = 0;
		}
		
	} while (ss == SEC_I_CONTINUE_NEEDED);
	
    if(ss == SEC_I_CONTINUE_NEEDED || ss == SEC_E_INCOMPLETE_MESSAGE || ss == SEC_I_INCOMPLETE_CREDENTIALS) {
		return;
	}
	
	if (ss != SEC_E_OK && !(isc_out_flags & ISC_RET_EXTENDED_ERROR)) {
		gchar *err_str = g_win32_error_message(ss);
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error initialising '%s' (%d)\n", err_str, (int)ss);
		g_free(err_str);
		
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
		return;
	}
	
	
	purple_input_remove(win32_data->handshake_handler);
	win32_data->handshake_handler = 0;
	
	ss = QueryContextAttributes(&win32_data->context, SECPKG_ATTR_STREAM_SIZES, &win32_data->Sizes);
	if (ss != SEC_E_OK) {
		gchar *err_str = g_win32_error_message(ss);
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error querying context '%s' (%d)\n", err_str, (int)ss);
		g_free(err_str);
		
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_HANDSHAKE_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
		return;
	}
	
	win32_data->max_extra = win32_data->Sizes.cbHeader + win32_data->Sizes.cbMaximumMessage + win32_data->Sizes.cbTrailer;
	win32_data->extra = g_renew(guchar, win32_data->extra, win32_data->max_extra);
	
	// Inconceivable !
	
	/// If a Verifier was given, hand control over to it
	if (gsc->verifier) {
		GList *peers;
		/// First, get the peer cert chain
		peers = purple_ssl_get_peer_certificates(gsc);

		if (peers != NULL) {
			/// Now kick off the verification process
			purple_certificate_verify(gsc->verifier,
					gsc->host,
					peers,
					ssl_win32_verified_cb,
					gsc);

			purple_certificate_destroy_list(peers);
		} else {
			// Ugh?
			gsc->connect_cb(gsc->connect_cb_data, gsc, cond);
		}
	} else {
		/// Otherwise, just call the "connection complete"
		/// callback. The verification was already done
		gsc->connect_cb(gsc->connect_cb_data, gsc, cond);
	}
}

static void
ssl_win32_connect(PurpleSslConnection *gsc)
{
	PurpleSslWin32Data *win32_data = g_new0(PurpleSslWin32Data, 1);
	
	SECURITY_STATUS ss;
	
	SCHANNEL_CRED sc_cred = { 0 };
    SecBufferDesc OutBuffer;
    SecBuffer OutBuffers[1];
	
	DWORD isc_flags = ISC_REQ_SEQUENCE_DETECT | ISC_REQ_REPLAY_DETECT |
	                  ISC_REQ_CONFIDENTIALITY | ISC_REQ_EXTENDED_ERROR |
					  ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_STREAM |
					  ISC_REQ_INTEGRITY;
	DWORD isc_out_flags;

	gsc->private_data = win32_data;
	
	sc_cred.dwVersion = SCHANNEL_CRED_VERSION;
	sc_cred.dwFlags = SCH_CRED_NO_DEFAULT_CREDS;
	if (gsc->verifier) {
		isc_flags |= ISC_REQ_MANUAL_CRED_VALIDATION;
		sc_cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
	} else {
		sc_cred.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION;
	}
	
	//TODO settings:
	if (TRUE) {
		sc_cred.dwMinimumCipherStrength = 128;
		sc_cred.dwMaximumCipherStrength = 4096;
		sc_cred.grbitEnabledProtocols = SP_PROT_SSL3_CLIENT |
		                                //SP_PROT_SSL2_CLIENT |
		                                SP_PROT_TLS1_CLIENT |
										SP_PROT_TLS1_0_CLIENT |
										SP_PROT_TLS1_1_CLIENT |
										SP_PROT_TLS1_2_CLIENT;
		sc_cred.dwFlags |= SCH_CRED_NO_SERVERNAME_CHECK;
	}
	
	ss = AcquireCredentialsHandle(NULL, UNISP_NAME, SECPKG_CRED_OUTBOUND, NULL,
								  &sc_cred, NULL, NULL, &win32_data->credentials, NULL);
	
	if(ss != SEC_E_OK) {
		gchar *err_str = g_win32_error_message(ss);
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error acquiring credentials handle '%s' (%d)\n", err_str, (int)ss);
		g_free(err_str);
			
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CONNECT_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
		return;
	}
	
    OutBuffers[0].pvBuffer   = NULL;
    OutBuffers[0].cbBuffer   = 0;
    OutBuffers[0].BufferType = SECBUFFER_TOKEN;

    OutBuffer.cBuffers = 1;
    OutBuffer.pBuffers = OutBuffers;
    OutBuffer.ulVersion = SECBUFFER_VERSION;
	
	ss = InitializeSecurityContextA(&win32_data->credentials, NULL, gsc->host, isc_flags, 0, 0, NULL, 0, &win32_data->context, &OutBuffer, &isc_out_flags, 0);
	
	if(!SUCCEEDED(ss)) {
		gchar *err_str = g_win32_error_message(ss);
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error initialising security context '%s' (%d)\n", err_str, (int)ss);
		g_free(err_str);
			
		if(gsc->error_cb != NULL)
			gsc->error_cb(gsc, PURPLE_SSL_CONNECT_FAILED,
				gsc->connect_cb_data);

		purple_ssl_close(gsc);
		return;
	}
	
    if (OutBuffers[0].cbBuffer != 0 && OutBuffers[0].pvBuffer != NULL)
    {
		int sent = send_all(gsc->fd, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
		//todo check error
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "TODO check %d\n", sent);
		
        FreeContextBuffer(OutBuffers[0].pvBuffer);
		OutBuffers[0].pvBuffer = NULL;
	}
	
	win32_data->max_extra = HANDSHAKE_BUFFER_SIZE;
	win32_data->extra = g_new0(guchar, win32_data->max_extra);
	win32_data->extra_len = 0;
	
	win32_data->handshake_handler = purple_input_add(gsc->fd,
		PURPLE_INPUT_READ, ssl_win32_handshake_cb, gsc);
}

static void
ssl_win32_close(PurpleSslConnection *gsc)
{
	PurpleSslWin32Data *win32_data = PURPLE_SSL_WIN32_DATA(gsc);
	
	SecBufferDesc OutBuffer;
	SecBuffer     OutBuffers[1];
    DWORD dwType = SCHANNEL_SHUTDOWN;
	
	if (!win32_data)
		return;
	
	if (win32_data->context.dwLower || win32_data->context.dwLower) {
		OutBuffers[0].pvBuffer   = &dwType;
		OutBuffers[0].cbBuffer   = sizeof(dwType);
		OutBuffers[0].BufferType = SECBUFFER_TOKEN;

		OutBuffer.cBuffers  = 1;
		OutBuffer.pBuffers  = OutBuffers;
		OutBuffer.ulVersion = SECBUFFER_VERSION;
		
		ApplyControlToken(&win32_data->context, &OutBuffer);
	
		DeleteSecurityContext(&win32_data->context);
	}

	if (win32_data->credentials.dwLower || win32_data->credentials.dwLower) {
		FreeCredentialsHandle(&win32_data->credentials);
	}
	
	g_free(win32_data->decrypted);
	g_free(win32_data->extra);
	
	g_free(win32_data);
	gsc->private_data = NULL;
}

static size_t
ssl_win32_read(PurpleSslConnection *gsc, void *data, size_t len)
{
	PurpleSslWin32Data *win32_data = PURPLE_SSL_WIN32_DATA(gsc);
	
	size_t ret = 0;
	SECURITY_STATUS ss;
	SecBufferDesc InBuffer;
	SecBuffer     InBuffers[4];
	size_t decrypted_remain = win32_data->decrypted_len - win32_data->decrypted_offset;
	
	if (decrypted_remain > 0) {
		size_t real_len = MIN(len, decrypted_remain);
		
		g_memmove(data, win32_data->decrypted + win32_data->decrypted_offset, real_len);
		win32_data->decrypted_offset += real_len;
		
		return real_len;
	}
	
	do {
		int err = wpurple_recv(gsc->fd, win32_data->extra + win32_data->extra_len, win32_data->max_extra - win32_data->extra_len, 0);
		
		if (err < 0 || (err == 0 && win32_data->extra_len == 0)) {
			return err;
		}

		win32_data->extra_len += err;
		
		InBuffers[0].pvBuffer     = win32_data->extra;
		InBuffers[0].cbBuffer     = win32_data->extra_len;
		InBuffers[0].BufferType   = SECBUFFER_DATA;

		InBuffers[1].BufferType   = SECBUFFER_EMPTY;
		InBuffers[2].BufferType   = SECBUFFER_EMPTY;
		InBuffers[3].BufferType   = SECBUFFER_EMPTY;

		InBuffer.ulVersion = SECBUFFER_VERSION;
		InBuffer.pBuffers = InBuffers;
		InBuffer.cBuffers = 4;

		ss = DecryptMessage(&win32_data->context, &InBuffer, 0, NULL);
	
	} while(ss == SEC_E_INCOMPLETE_MESSAGE);
	
	if(!SUCCEEDED(ss)) {
		gchar *err_str = g_win32_error_message(ss);
		purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error reading data '%s' (%d)\n", err_str, (int)ss);
		g_free(err_str);
		errno = EIO;
		
		return -1;
	}
	
	if (InBuffers[1].BufferType == SECBUFFER_DATA)
	{
		ret = MIN(len, InBuffers[1].cbBuffer);
		g_memmove(data, InBuffers[1].pvBuffer, ret);
		
		// Save leftovers for supper
		if (InBuffers[1].cbBuffer > ret) {
			g_free(win32_data->decrypted);
			win32_data->decrypted_len = InBuffers[1].cbBuffer - ret;
			win32_data->decrypted = g_memdup(InBuffers[1].pvBuffer + ret, win32_data->decrypted_len);
			win32_data->decrypted_offset = 0;
		}
	}
	
	if (InBuffers[3].BufferType == SECBUFFER_EXTRA && InBuffers[1].pvBuffer != NULL && InBuffers[1].cbBuffer > 0)
	{
		win32_data->extra_len = InBuffers[3].cbBuffer;
		g_memmove(win32_data->extra, InBuffers[3].pvBuffer, InBuffers[3].cbBuffer);
	} else {
		win32_data->extra_len = 0;
	}

	return ret;
}

static size_t
ssl_win32_write(PurpleSslConnection *gsc, const void *data, size_t len)
{
	PurpleSslWin32Data *win32_data = PURPLE_SSL_WIN32_DATA(gsc);
	
	SECURITY_STATUS ss;
	SecBufferDesc OutBuffer;
	SecBuffer     OutBuffers[4];
	guchar *header;
	guchar *footer;
	guchar *body;
	size_t sent = 0;
	
	header = g_new0(guchar, win32_data->Sizes.cbHeader);
	body = g_new0(guchar, win32_data->Sizes.cbMaximumMessage);
	footer = g_new0(guchar, win32_data->Sizes.cbTrailer);
	
	OutBuffers[0].pvBuffer   = header;
	OutBuffers[0].cbBuffer   = win32_data->Sizes.cbHeader;
	OutBuffers[0].BufferType = SECBUFFER_STREAM_HEADER;

	OutBuffers[2].pvBuffer   = footer;
	OutBuffers[2].cbBuffer   = win32_data->Sizes.cbTrailer;
	OutBuffers[2].BufferType = SECBUFFER_STREAM_TRAILER;

	OutBuffers[3].pvBuffer   = SECBUFFER_EMPTY;
	OutBuffers[3].cbBuffer   = SECBUFFER_EMPTY;
	OutBuffers[3].BufferType = SECBUFFER_EMPTY;

    OutBuffer.ulVersion      = SECBUFFER_VERSION;
    OutBuffer.cBuffers       = 4;
    OutBuffer.pBuffers       = OutBuffers;
	
	while (sent < len) {
		int rval;
		
		size_t bodylen = len - sent;
		if (bodylen > win32_data->Sizes.cbMaximumMessage)
			bodylen = win32_data->Sizes.cbMaximumMessage;
		
		g_memmove(body, data + sent, bodylen);
		
		OutBuffers[1].pvBuffer   = body;
		OutBuffers[1].cbBuffer   = bodylen;
		OutBuffers[1].BufferType = SECBUFFER_DATA;
		
		ss = EncryptMessage(&win32_data->context, 0, &OutBuffer, 0);
		
		if(!SUCCEEDED(ss)) {
			gchar *err_str = g_win32_error_message(ss);
			purple_debug_error(SSL_WIN32_PLUGIN_ID, "Error writing data '%s' (%d)\n", err_str, (int)ss);
			g_free(err_str);
			errno = EIO;
			
			return -1;
		}
		
		rval = send_all(gsc->fd, OutBuffers[0].pvBuffer, OutBuffers[0].cbBuffer, 0);
		if (rval != OutBuffers[0].cbBuffer)
			return rval;
		
		rval = send_all(gsc->fd, OutBuffers[1].pvBuffer, OutBuffers[1].cbBuffer, 0);
		if (rval != OutBuffers[1].cbBuffer)
			return rval;
		
		rval = send_all(gsc->fd, OutBuffers[2].pvBuffer, OutBuffers[2].cbBuffer, 0);
		if (rval != OutBuffers[2].cbBuffer)
			return rval;
		
		sent += bodylen;
	}
	
	g_free(header);
	g_free(footer);
	g_free(body);
	
	return sent;
}


static GList *
ssl_win32_peer_certs(PurpleSslConnection *gsc)
{
	PurpleSslWin32Data *win32_data = PURPLE_SSL_WIN32_DATA(gsc);
	PCCERT_CONTEXT pCertContext = NULL, pIssuerCert, pCurrentCert;
	PurpleCertificate *newcrt = NULL;
	GList *peer_certs = NULL;
    DWORD dwVerificationFlags;
	SECURITY_STATUS ss;
	
	ss = QueryContextAttributes(&win32_data->context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &pCertContext);
	g_return_val_if_fail(ss == SEC_E_OK, NULL);
	
	pCurrentCert = pCertContext;
	while(pCurrentCert != NULL) {
		newcrt = g_new0(PurpleCertificate, 1);
		newcrt->scheme = &x509_win32;
		newcrt->data = (PCERT_CONTEXT) CertDuplicateCertificateContext(pCurrentCert);
		peer_certs = g_list_append(peer_certs, newcrt);
		
		dwVerificationFlags = 0;
		pIssuerCert = CertGetIssuerCertificateFromStore(pCertContext->hCertStore, pCurrentCert, NULL, &dwVerificationFlags);
		CertFreeCertificateContext(pCurrentCert);
		
		if (!pIssuerCert) {
			break;
		}
		
		pCurrentCert = pIssuerCert;
	}
	
	return peer_certs;
}

static PurpleSslOps ssl_ops =
{
	ssl_win32_init,
	ssl_win32_uninit,
	ssl_win32_connect,
	ssl_win32_close,
	ssl_win32_read,
	ssl_win32_write,
	ssl_win32_peer_certs,

	/* padding */
	NULL,
	NULL,
	NULL
};











#ifndef CERT_NAME_ATTR_TYPE
WINCRYPT32API DWORD WINAPI CertGetNameStringA(IN PCCERT_CONTEXT pCertIntext, IN DWORD dwType, IN DWORD dwFlags, IN void *pvTypePara, OUT OPTIONAL LPSTR pszNameString, IN DWORD cchNameString);
WINCRYPT32API DWORD WINAPI CertGetNameStringW(IN PCCERT_CONTEXT pCertIntext, IN DWORD dwType, IN DWORD dwFlags, IN void *pvTypePara, OUT OPTIONAL LPWSTR pszNameString, IN DWORD cchNameString);
#define CERT_NAME_ATTR_TYPE 3
#endif

/** Imports a PEM-formatted X.509 certificate from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A newly allocated Certificate structure of the x509_nss scheme
 */
 
 //see capi_pem.cpp
static PurpleCertificate *
x509_import_from_file(const gchar *filename)
{
	PCCERT_CONTEXT pCertContext = NULL;
	BYTE *derPubKey = NULL;
	DWORD derPubKeyLen = 0;
	gchar *rawcert;
	gsize len = 0;
	PurpleCertificate *crt;
	
	g_return_val_if_fail(filename != NULL, NULL);

	purple_debug_info(SSL_WIN32_PLUGIN_ID "/x509", "Loading certificate from %s\n", filename);

	/* Load the raw data up */
	if (!g_file_get_contents(filename, &rawcert, &len, NULL)) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Unable to read certificate file.\n");
		return NULL;
	}

	if (len == 0) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Certificate file has no contents!\n");
		if (rawcert)
			g_free(rawcert);
		return NULL;
	}
	
	// Convert from PEM to DER
	CryptStringToBinaryA(rawcert, len, CRYPT_STRING_ANY, NULL, &derPubKeyLen, NULL, NULL);
	derPubKey = g_new0(BYTE, derPubKeyLen);
	if (!CryptStringToBinaryA(rawcert, len, CRYPT_STRING_ANY, derPubKey, &derPubKeyLen, NULL, NULL)) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Couldn't convert PEM to DER %lu\n", GetLastError());
		g_free(derPubKey);
		g_free(rawcert);
		return NULL;
	}
	g_free(rawcert);
	
	// Convert from DER to CERT_CONTEXT
	pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, derPubKey, derPubKeyLen);
	g_free(derPubKey);
	if (pCertContext == NULL) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Couldn't convert DER to CERT_CONTEXT %lu\n", GetLastError());
        return NULL;
	}
	
	crt = g_new0(PurpleCertificate, 1);
	crt->scheme = &x509_win32;
	crt->data = (PCERT_CONTEXT) pCertContext;

	return crt;
}


/** Imports a number of PEM-formatted X.509 certificates from the specified file.
 * @param filename Filename to import from. Format is PEM
 *
 * @return A GSList of newly allocated Certificate structures of the x509_nss scheme
 */
static GSList *
x509_importcerts_from_file(const gchar *filename)
{
	PCCERT_CONTEXT pCertContext = NULL;
	BYTE *derPubKey = NULL;
	DWORD derPubKeyLen = 0;
	gchar *rawcert, *begin, *end;
	gsize len = 0;
	PurpleCertificate *crt;
	GSList *crts = NULL;
	
	g_return_val_if_fail(filename != NULL, NULL);

	purple_debug_info(SSL_WIN32_PLUGIN_ID "/x509", "Loading certificate from %s\n", filename);

	/* Load the raw data up */
	if (!g_file_get_contents(filename, &rawcert, &len, NULL)) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Unable to read certificate file.\n");
		return NULL;
	}

	if (len == 0) {
		purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Certificate file has no contents!\n");
		if (rawcert)
			g_free(rawcert);
		return NULL;
	}
	
	begin = rawcert;
	while((end = strstr(begin, "-----END CERTIFICATE-----")) != NULL) {
		end += sizeof("-----END CERTIFICATE-----") - 1;
	
		// Convert from PEM to DER
		CryptStringToBinaryA(begin, (end-begin), CRYPT_STRING_ANY, NULL, &derPubKeyLen, NULL, NULL);
		derPubKey = g_new0(BYTE, derPubKeyLen);
		if (!CryptStringToBinaryA(begin, (end-begin), CRYPT_STRING_ANY, derPubKey, &derPubKeyLen, NULL, NULL)) {
			purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Couldn't convert PEM to DER %lu\n", GetLastError());
			g_free(derPubKey);
			g_free(rawcert);
			return NULL;
		}
		
		// Convert from DER to CERT_CONTEXT
		pCertContext = CertCreateCertificateContext(X509_ASN_ENCODING, derPubKey, derPubKeyLen);
		g_free(derPubKey);
		if (pCertContext == NULL) {
			purple_debug_error(SSL_WIN32_PLUGIN_ID "/x509", "Couldn't convert DER to CERT_CONTEXT %lu\n", GetLastError());
			g_free(rawcert);
			return NULL;
		}
		
		crt = g_new0(PurpleCertificate, 1);
		crt->scheme = &x509_win32;
		crt->data = (PCERT_CONTEXT) pCertContext;

		crts = g_slist_prepend(crts, crt);
		begin = end;
	}
	g_free(rawcert);
	
	return crts;
}


/**
 * Exports a PEM-formatted X.509 certificate to the specified file.
 * @param filename Filename to export to. Format will be PEM
 * @param crt      Certificate to export
 *
 * @return TRUE if success, otherwise FALSE
 */
static gboolean
x509_export_certificate(const gchar *filename, PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD pemlen = 0;
	gchar *pemcrt;
	gboolean ret = FALSE;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_win32, FALSE);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, FALSE);
	
	if (!CryptBinaryToStringA(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, NULL, &pemlen)) {
		return FALSE;
	}
	pemcrt = g_new0(gchar, pemlen);
	if (!CryptBinaryToStringA(pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, CRYPT_STRING_BASE64HEADER, pemcrt, &pemlen)) {
		return FALSE;
	}

	ret = purple_util_write_data_to_file_absolute(filename, pemcrt, -1);
	
	g_free(pemcrt);

	return ret;
}

static PurpleCertificate *
x509_copy_certificate(PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	PurpleCertificate *newcrt;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);

	/* Create the certificate copy */
	newcrt = g_new0(PurpleCertificate, 1);
	newcrt->scheme = &x509_win32;
	newcrt->data = (PCERT_CONTEXT) CertDuplicateCertificateContext(pCertContext);

	return newcrt;
}

/** Frees a Certificate
 *
 *  Destroys a Certificate's internal data structures and frees the pointer
 *  given.
 *  @param crt  Certificate instance to be destroyed. It WILL NOT be destroyed
 *              if it is not of the correct CertificateScheme. Can be NULL
 *
 */
static void
x509_destroy_certificate(PurpleCertificate * crt)
{
	PCCERT_CONTEXT pCertContext = NULL;

	g_return_if_fail(crt);
	g_return_if_fail(crt->scheme == &x509_win32);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_if_fail(pCertContext);

	CertFreeCertificateContext(pCertContext);

	g_free(crt);
}

/** Determines whether one certificate has been issued and signed by another
 *
 * @param crt       Certificate to check the signature of
 * @param issuer    Issuer's certificate
 *
 * @return TRUE if crt was signed and issued by issuer, otherwise FALSE
 * @TODO  Modify this function to return a reason for invalidity?
 */
static gboolean
x509_signed_by(PurpleCertificate *crt, PurpleCertificate *issuer)
{
	PCCERT_CONTEXT pCertContext = NULL;
	PCCERT_CONTEXT pIssuerCertContext = NULL;
	PCERT_INFO pCertInfo = NULL;
	PCERT_INFO pIssuerCertInfo = NULL;

	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);
	g_return_val_if_fail(issuer->scheme == &x509_win32, NULL);
	
	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, FALSE);
	pCertInfo = pCertContext->pCertInfo;
	g_return_val_if_fail(pCertInfo, FALSE);
	
	pIssuerCertContext = X509_WIN32_DATA(issuer);
	g_return_val_if_fail(pIssuerCertContext, FALSE);
	pIssuerCertInfo = pIssuerCertContext->pCertInfo;
	g_return_val_if_fail(pIssuerCertInfo, FALSE);
	
	if (pCertInfo->IssuerUniqueId.cbData != pIssuerCertInfo->SubjectUniqueId.cbData ||
			memcmp(pCertInfo->IssuerUniqueId.pbData, pIssuerCertInfo->SubjectUniqueId.pbData, pCertInfo->IssuerUniqueId.cbData) != 0) {
		return FALSE;
	}
	
	return TRUE;
}

static GByteArray *
x509_sha1sum(PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	GByteArray *sha1sum;
	DWORD hashlen = 20; // Size of an sha1sum

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);
	
	sha1sum = g_byte_array_sized_new(hashlen);
	sha1sum->len = hashlen;
	
	if(!CryptHashCertificate(0, CALG_SHA1, 0, pCertContext->pbCertEncoded, pCertContext->cbCertEncoded, sha1sum->data, &hashlen))
    {
		g_byte_array_free(sha1sum, TRUE);
        return NULL;
    }
	
	return sha1sum;
}

static gchar *
x509_dn (PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD namelen = 0;
	gchar *subject;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);
	
	namelen = CertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_OID_NAME_STR, NULL, 0);
	g_return_val_if_fail(namelen, NULL);
	subject = g_new0(gchar, namelen);
	CertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Subject, CERT_OID_NAME_STR, subject, namelen);

	return subject;
}

static gchar *
x509_issuer_dn (PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD namelen = 0;
	gchar *issuer;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);
	
	//TODO wide version of function
	namelen = CertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_OID_NAME_STR, NULL, 0);
	g_return_val_if_fail(namelen, NULL);
	issuer = g_new0(gchar, namelen);
	//TODO wide version of function
	CertNameToStrA(X509_ASN_ENCODING, &pCertContext->pCertInfo->Issuer, CERT_OID_NAME_STR, issuer, namelen);

	return issuer;
}

static gchar *
x509_common_name (PurpleCertificate *crt)
{
	PCCERT_CONTEXT pCertContext = NULL;
	DWORD namelen = 0;
	gchar *name;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);

	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);
	
	//TODO wide version of function
	namelen = CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, NULL, 0);
	name = g_new0(gchar, namelen);
	//TODO wide version of function
	CertGetNameStringA(pCertContext, CERT_NAME_ATTR_TYPE, 0, szOID_COMMON_NAME, name, namelen);
	
	return name;
}

static gboolean
x509_check_name (PurpleCertificate *crt, const gchar *name)
{
	PCCERT_CONTEXT pCertContext = NULL;
	gchar *cert_hostname;
	DWORD hostlen = 0;
	int cmp;
	
	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);
	
	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);
	
	//TODO wide version of function
	hostlen = CertGetNameStringA(pCertContext, CERT_NAME_DNS_TYPE, 0, NULL, NULL, 0);
	if (hostlen == 0)
		return FALSE;
	
	cert_hostname = g_new0(gchar, hostlen);
	//TODO wide version of function
	CertGetNameStringA(pCertContext, CERT_NAME_DNS_TYPE, 0, NULL, cert_hostname, hostlen);
	
	//TODO multidomain certs?
	if (*cert_hostname == '*') {
		// Wildcard cert
		int namelen = strlen(name);
		cmp = g_ascii_strcasecmp(cert_hostname + 1, name + namelen - hostlen + 2);
	} else {
		cmp = g_ascii_strcasecmp(cert_hostname, name);
	}
	g_free(cert_hostname);
	
	return (cmp == 0);
}

static gboolean
x509_times (PurpleCertificate *crt, time_t *activation, time_t *expiration)
{
	PCCERT_CONTEXT pCertContext = NULL;

	g_return_val_if_fail(crt, NULL);
	g_return_val_if_fail(crt->scheme == &x509_win32, NULL);
	
	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, NULL);

	if (activation) {
		FILETIME notBefore = pCertContext->pCertInfo->NotBefore;
		ULARGE_INTEGER t;
		memcpy(&t, &notBefore, sizeof(t));
		
		*activation = t.QuadPart * 0.0000001 - 11644473600.0;
	}
	if (expiration) {
		FILETIME notAfter = pCertContext->pCertInfo->NotAfter;
		ULARGE_INTEGER t;
		memcpy(&t, &notAfter, sizeof(t));
		
		*expiration = t.QuadPart * 0.0000001 - 11644473600.0;
	}

	return TRUE;
}

static gboolean
x509_register_trusted_tls_cert(PurpleCertificate *crt, gboolean ca)
{
	HCERTSTORE hCertStore;
	PCCERT_CONTEXT pCertContext = NULL;

	g_return_val_if_fail(crt, FALSE);
	g_return_val_if_fail(crt->scheme == &x509_win32, FALSE);
	
	pCertContext = X509_WIN32_DATA(crt);
	g_return_val_if_fail(pCertContext, FALSE);
	
	hCertStore = CertOpenSystemStoreA(0, ca ? "CA" : "MY");
	if (!hCertStore)
		return FALSE;
	
	if (!CertAddCertificateContextToStore(hCertStore, pCertContext,
                                       CERT_STORE_ADD_REPLACE_EXISTING, 0)) {
		CertCloseStore(hCertStore, 0);
		return FALSE;
	}
	
	CertCloseStore(hCertStore, 0);
	return TRUE;
}

#ifndef CERT_TRUST_IS_EXPLICIT_DISTRUST
#	define CERT_TRUST_IS_EXPLICIT_DISTRUST 0x04000000
#endif
#ifndef CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT
#	define CERT_TRUST_HAS_NOT_SUPPORTED_CRITICAL_EXT 0x08000000
#endif
#ifndef CERT_TRUST_HAS_WEAK_SIGNATURE
#	define CERT_TRUST_HAS_WEAK_SIGNATURE 0x00100000
#endif

static PurpleCertificateInvalidityFlags
_map_chainerror_to_flags(DWORD error_status) {
	PurpleCertificateInvalidityFlags flags = PURPLE_CERTIFICATE_NO_PROBLEMS;
	
	
	/*  PURPLE_CERTIFICATE_UNKNOWN_ERROR = -1, PURPLE_CERTIFICATE_NO_PROBLEMS = 0, PURPLE_CERTIFICATE_NON_FATALS_MASK = 0x0000FFFF, PURPLE_CERTIFICATE_SELF_SIGNED = 0x01, 
  PURPLE_CERTIFICATE_CA_UNKNOWN = 0x02, PURPLE_CERTIFICATE_NOT_ACTIVATED = 0x04, PURPLE_CERTIFICATE_EXPIRED = 0x08, PURPLE_CERTIFICATE_NAME_MISMATCH = 0x10, 
  PURPLE_CERTIFICATE_NO_CA_POOL = 0x20, PURPLE_CERTIFICATE_FATALS_MASK = 0xFFFF0000, PURPLE_CERTIFICATE_INVALID_CHAIN = 0x10000, PURPLE_CERTIFICATE_REVOKED = 0x20000, 
  PURPLE_CERTIFICATE_LAST = 0x40000  */
	
	if (error_status & (CERT_TRUST_IS_NOT_TIME_VALID | CERT_TRUST_CTL_IS_NOT_TIME_VALID)) {
		flags |= PURPLE_CERTIFICATE_EXPIRED;
	}
	if (error_status & CERT_TRUST_IS_REVOKED) {
		flags |= PURPLE_CERTIFICATE_REVOKED;
	}
	if (error_status & (CERT_TRUST_IS_NOT_VALID_FOR_USAGE | CERT_TRUST_CTL_IS_NOT_VALID_FOR_USAGE)) {
		flags |= PURPLE_CERTIFICATE_INVALID_CHAIN;
	}
	if (error_status & (CERT_TRUST_IS_UNTRUSTED_ROOT | CERT_TRUST_IS_EXPLICIT_DISTRUST | CERT_TRUST_IS_PARTIAL_CHAIN)) {
		flags |= PURPLE_CERTIFICATE_CA_UNKNOWN;
	}
	
	return flags;
}

static void
x509_verify_cert(PurpleCertificateVerificationRequest *vrq, PurpleCertificateInvalidityFlags *flags)
{
	CERT_CHAIN_PARA chain_para; // for checking the cert chain
	SSL_EXTRA_CERT_CHAIN_POLICY_PARA extra_policy_para; // for checking the cert name
	CERT_CHAIN_POLICY_PARA policy_para;
	CERT_CHAIN_POLICY_STATUS policy_status;
	
	PurpleCertificate *first_cert = vrq->cert_chain->data;
	PCCERT_CONTEXT pCertContext = NULL;
	static const LPCSTR usage[] = {
		szOID_PKIX_KP_SERVER_AUTH,
		szOID_SERVER_GATED_CRYPTO,
		szOID_SGC_NETSCAPE
	};
	gunichar2 *unicode_hostname; //vrq->subject_name
	
	DWORD chain_flags = CERT_CHAIN_CACHE_END_CERT |
                        CERT_CHAIN_REVOCATION_CHECK_CHAIN_EXCLUDE_ROOT |
						CERT_CHAIN_REVOCATION_CHECK_CACHE_ONLY; // or CERT_STATUS_REV_CHECKING_ENABLED ?
	PCCERT_CHAIN_CONTEXT chain_context;

	g_return_if_fail(first_cert);
	g_return_if_fail(first_cert->scheme == &x509_win32);
	
	pCertContext = X509_WIN32_DATA(first_cert);
	g_return_if_fail(pCertContext);
  
	memset(&chain_para, 0, sizeof(chain_para));
	chain_para.cbSize = sizeof(chain_para);
	chain_para.RequestedUsage.dwType = USAGE_MATCH_TYPE_OR;
	chain_para.RequestedUsage.Usage.cUsageIdentifier = 3;
	chain_para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
	
	if (!CertGetCertificateChain(NULL,
	                             pCertContext,
	                             NULL,  // current system time
	                             NULL, //optional certificate store
	                             &chain_para,
	                             chain_flags,
	                             NULL,  // reserved
	                             &chain_context))
	{
		*flags |= PURPLE_CERTIFICATE_UNKNOWN_ERROR;
		return;
	}
	
	if (chain_context->TrustStatus.dwErrorStatus & CERT_TRUST_IS_NOT_VALID_FOR_USAGE) {
		chain_para.RequestedIssuancePolicy.Usage.cUsageIdentifier = 0;
		chain_para.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = NULL;
		CertFreeCertificateChain(chain_context);
		
		if (!CertGetCertificateChain(NULL,
									 pCertContext,
									 NULL,  // current system time
									 NULL, //optional certificate store
									 &chain_para,
									 chain_flags,
									 NULL,  // reserved
									 &chain_context))
		{
			*flags |= PURPLE_CERTIFICATE_UNKNOWN_ERROR;
			return;
		}
	}
	
	*flags |= _map_chainerror_to_flags(chain_context->TrustStatus.dwErrorStatus);
	
	unicode_hostname = g_utf8_to_utf16(vrq->subject_name, -1, NULL, NULL, NULL);
	
	memset(&extra_policy_para, 0, sizeof(extra_policy_para));
	extra_policy_para.cbSize = sizeof(extra_policy_para);
	extra_policy_para.dwAuthType = AUTHTYPE_SERVER;
	extra_policy_para.pwszServerName = unicode_hostname;
	
	memset(&policy_para, 0, sizeof(policy_para));
	policy_para.cbSize = sizeof(policy_para);
	policy_para.dwFlags = 0;
	policy_para.pvExtraPolicyPara = &extra_policy_para;
	
	memset(&policy_status, 0, sizeof(policy_status));
	policy_status.cbSize = sizeof(policy_status);
	
	if (!CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL,
                                          chain_context,
                                          &policy_para,
                                          &policy_status)) 
	{
		*flags |= PURPLE_CERTIFICATE_UNKNOWN_ERROR;
		
		g_free(unicode_hostname);
		CertFreeCertificateChain(chain_context);
		return;
	}
	
	if (policy_status.dwError) {
		*flags |= _map_chainerror_to_flags(policy_status.dwError);
	}
	
	g_free(unicode_hostname);
	CertFreeCertificateChain(chain_context);
}

static PurpleCertificateScheme x509_win32 = {
	"x509",                          /// Scheme name 
	N_("X.509 Certificates"),        /// User-visible scheme name 
	x509_import_from_file,           /// Certificate import function 
	x509_export_certificate,         /// Certificate export function 
	x509_copy_certificate,           /// Copy 
	x509_destroy_certificate,        /// Destroy cert 
	x509_signed_by,                  /// Signed-by 
	x509_sha1sum,                    /// SHA1 fingerprint 
	x509_dn,                         /// Unique ID 
	x509_issuer_dn,                  /// Issuer Unique ID 
	x509_common_name,                /// Subject name 
	x509_check_name,                 /// Check subject name 
	x509_times,                      /// Activation/Expiration time 
	x509_importcerts_from_file,      /// Multiple certificate import function 
	x509_register_trusted_tls_cert,  /// Optional, Register a certificate as trusted for TLS - since libpurple 2.10.10
	x509_verify_cert,                /// Optional, Verify that the specified cert chain is trusted - since libpurple 2.10.10
	NULL
};





static gboolean
plugin_load(PurplePlugin *plugin)
{
	/// Only load if NSS hasn't
	if (!purple_ssl_get_ops()) {
		purple_ssl_set_ops(&ssl_ops);
	}
	
	ssl_win32_init_ssl();
	
	/// Destory NSS's certificate scheme
	purple_certificate_unregister_scheme(purple_certificate_find_scheme("x509"));

	/// Register the X.509 functions we provide
	purple_certificate_register_scheme(&x509_win32);

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin *plugin)
{
	if (purple_ssl_get_ops() == &ssl_ops) {
		purple_ssl_set_ops(NULL);
	}

	/// Unregister our X.509 functions
	purple_certificate_unregister_scheme(&x509_win32);

	return TRUE;
}

static PurplePluginInfo info =
{
	PURPLE_PLUGIN_MAGIC,
	PURPLE_MAJOR_VERSION,
	PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,                             /**< type           */
	NULL,                                             /**< ui_requirement */
	PURPLE_PLUGIN_FLAG_INVISIBLE,                       /**< flags          */
	NULL,                                             /**< dependencies   */
	PURPLE_PRIORITY_DEFAULT,                            /**< priority       */

	SSL_WIN32_PLUGIN_ID,                             /**< id             */
	N_("Win32"),                                        /**< name           */
	DISPLAY_VERSION,                                  /**< version        */
	                                                  /**  summary        */
	N_("Provides SSL support through Windows STunnel functions"),
	                                                  /**  description    */
	N_("Provides SSL support through Windows STunnel functions"),
	"Eion Robb <eionrobb@gmail.com>",
	PURPLE_WEBSITE,                                     /**< homepage       */

	plugin_load,                                      /**< load           */
	plugin_unload,                                    /**< unload         */
	NULL,                                             /**< destroy        */

	NULL,                                             /**< ui_info        */
	NULL,                                             /**< extra_info     */
	NULL,                                             /**< prefs_info     */
	NULL,                                             /**< actions        */

	/* padding */
	NULL,
	NULL,
	NULL,
	NULL
};

static gboolean(*nss_load)(PurplePlugin *plugin) = NULL;
static gboolean(*nss_unload)(PurplePlugin *plugin) = NULL;

static gboolean
hijack_nss_load(PurplePlugin *plugin) {
	if (nss_load != NULL)
		nss_load(plugin);
	plugin_load(plugin);
	
	return TRUE;
}
static gboolean
hijack_nss_unload(PurplePlugin *plugin) {
	if (nss_unload != NULL)
		nss_unload(plugin);
	plugin_unload(plugin);
	
	return TRUE;
}

static void
init_plugin(PurplePlugin *plugin)
{
	PurplePlugin *sslnss;
	
	sslnss = purple_plugins_find_with_id("ssl-nss");
	if (sslnss) {
		purple_debug_info(SSL_WIN32_PLUGIN_ID, "Hijacking load/unload functions from ssl-nss\n");
		
		nss_load = sslnss->info->load;
		nss_unload = sslnss->info->unload;
		
		sslnss->info->load = hijack_nss_load;
		sslnss->info->unload = hijack_nss_unload;
	}
}

PURPLE_INIT_PLUGIN(ssl_win32, init_plugin, info)