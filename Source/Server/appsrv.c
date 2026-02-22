/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#include "appsrv.h"
#include "qstp.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"

#if defined(QSTP_DEBUG_MODE)
//#	define SERVER_ENCODING_TEST
#endif

static qstp_server_signature_key m_server_signature_key;

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0U)
		{
			server_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("");
			server_print_prompt();
		}
	}
}

static void server_print_error(qstp_errors error)
{
	const char* msg;

	msg = qstp_error_to_string(error);

	if (msg != NULL)
	{
		server_print_message(msg);
	}
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("QSTP: Server Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Protocol server.");
	qsc_consoleutils_print_line("Release:   v1.4.0.0a (A4)");
	qsc_consoleutils_print_line("Date:      February 21, 2026");
	qsc_consoleutils_print_line("Contact:   contact@qrcscorp.ca");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, QSTP_CERTIFICATE_DEFAULT_DOMAIN);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_SERVER_DIRECTORY_PATH);

		if (qsc_folderutils_directory_exists(fpath) == false)
		{
			res = qsc_folderutils_create_directory(fpath);
		}
	}

	return res;
}

static bool server_get_certificate_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		char issuer[QSTP_CERTIFICATE_ISSUER_SIZE] = { 0 };

		qsc_folderutils_append_delimiter(fpath);
		qstp_server_get_issuer(issuer);
		qsc_stringutils_to_lowercase(issuer);
		qsc_stringutils_concat_strings(fpath, pathlen, issuer);
	}
	
	return res;
}

static bool server_get_root_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_ROOT_CERTIFICATE_NAME);
	}
	
	return res;
}

static bool server_get_key_path(char* fpath, size_t pathlen)
{
	bool res;

	res = server_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_SERVER_PRIVATE_KEY_NAME);
	}

	return res;
}

static bool server_key_generate(void)
{
	qstp_server_certificate cert = { 0 };
	char issuer[QSTP_CERTIFICATE_ISSUER_SIZE] = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	
	bool res;

	/* Note: ex. mydomain_srv1.qrc */
	qstp_server_get_issuer(issuer);
	/* create the master key */
	qstp_server_key_generate(&m_server_signature_key, issuer, QSTP_CERTIFICATE_DEFAULT_DURATION_DAYS);

	/* extract the server certificate and write to file */
	qstp_server_certificate_extract(&cert, &m_server_signature_key);

	server_get_certificate_path(fpath, sizeof(fpath));
	res = qstp_server_certificate_to_file(&cert, fpath);
	
	if (res == true)
	{
		server_print_prompt();
		qsc_consoleutils_print_safe("The server certificate has been saved to: ");
		qsc_consoleutils_print_line(fpath);
		server_print_message("The certificate must be signed by the root server before use.");

		/* get the key state path */
		qsc_stringutils_clear_string(fpath);
		server_get_key_path(fpath, sizeof(fpath));
		/* copy the root key to file */
		res = qstp_server_key_to_file(&m_server_signature_key, fpath);
	}

	return res;
}

#if defined(SERVER_ENCODING_TEST)
static void qstp_server_self_tests(qstp_server_certificate* cert)
{

	if (qstp_test_server_certificate_serialization(cert) == true)
	{
		server_print_message("Passed server certificate serialization test.");
	}
	else
	{
		server_print_message("Failed server certificate serialization test.");
	}

	if (qstp_test_server_certificate_encoding(cert) == true)
	{
		server_print_message("Passed server certificate encoding test.");
		qstp_server_certificate_print(cert);
	}
	else
	{
		server_print_message("Failed server certificate encoding test.");
	}

	server_print_message("");
}
#endif

static bool server_root_fetch_verification_key(qstp_root_certificate* root, uint8_t* exverkey)
{
	(void)root;
	(void)exverkey;
	/* Beyond example scope. This is where you would use the root certificate's
	* authority field to lookup a certificate domain, and the keyid serial number 
	* to fetch and external signature verification key that anchors the root certificate.
	* The external signature scheme must match the algorithm and parameters of 
	* the signature scheme selected for QSTP. Alternatively, the authority signature 
	* verification key can be embedded in the application itself. */
	
	return false;
}

static bool server_key_dialogue(void)
{
	qstp_root_certificate root = { 0 };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t slen;
	bool res;

	res = false;
	server_get_key_path(fpath, sizeof(fpath));

	if (qsc_fileutils_exists(fpath) == true)
	{
		if (qstp_server_file_to_key(&m_server_signature_key, fpath) == true)
		{
			qstp_server_certificate cert = { 0 };

			qsc_memutils_clear(fpath, sizeof(fpath));
			server_get_certificate_path(fpath, sizeof(fpath));

			if (qstp_server_file_to_certificate(&cert, fpath) == true)
			{
				if (qsc_memutils_zeroed(cert.rootser, QSTP_CERTIFICATE_SERIAL_SIZE) == true)
				{
					server_print_message("The certificate has not been signed by the root.");
				}
				else
				{
					server_get_root_path(fpath, sizeof(fpath));

					if (qsc_fileutils_exists(fpath) == true)
					{
						if (qstp_root_file_to_certificate(&root, fpath) == true)
						{
#if defined(QSTP_EXTERNAL_SIGNED_ROOT)
							/* External signed certificate check: externally signed test requires the 
							* verification key as a parameter. The server looks up the authority tag
							* of the root certificate to get the yyyyyyyyyyyyy, then the keyid field to get
							* the certificate signature verification key. A root certificate failure 
							* must halt the connection process and propagate the error.
							* Look up the authority and keyid fields on the root certificate
							* and fetch the verification key, then load the key and verify the 
							* root certificate using the external verification key. */
							
							/* uint8_t exverkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE] = { 0U };

							if (server_root_fetch_verification_key(&root, exverkey) == true && 
								qstp_root_certificate_verify(&root, exverkey) == true) */
#else
							/* Self signed root certificate check: verifies the signature against the 
							* root certificates verification key, then hashes the root certificate and 
							* compares the hash to the signed message.
							*/
							if (qstp_root_certificate_verify(&root) == true)
#endif
							{
								/* Important! create the session transcript hash
								* This hash must be created when the signature key is loaded by the application.
								*/
								qstp_server_root_certificate_hash(m_server_signature_key.schash, &root, &cert);
								res = true;

#if defined(SERVER_ENCODING_TEST)
								/* local encoding and serialization tests */
								qstp_server_self_tests(&cert);
#endif
							}
						}
					}
				}
			}
		}
	}
	else
	{
		/* get the root certificate */
		server_print_message("Enter the path of the public root certificate:");
		server_print_prompt();
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath));

		if (slen > 0 &&
			qsc_fileutils_exists(fpath) == true &&
			qsc_stringutils_string_contains(fpath, QSTP_ROOT_PUBLIC_CERTIFICATE_NAME) == true)
		{
			if (qstp_root_file_to_certificate(&root, fpath) == true)
			{
				char rpath[QSC_SYSTEM_MAX_PATH] = { 0 };
				server_get_root_path(rpath, sizeof(rpath));

				if (qstp_root_certificate_to_file(&root, rpath) == true)
				{
					if (server_key_generate() == false)
					{
						server_print_message("Server key generation has failed.");
					}
					else
					{
						server_print_message("Use the root server to sign the certificate.");
						res = false;
					}
				}
				else
				{
					server_print_message("The root certificate could not be saved.");
				}
			}
			else
			{
				server_print_message("The root certificate is invalid.");
			}
		}
	}

	return res;
}

static void server_send_echo(qstp_connection_state* cns, const char* message, size_t msglen)
{
	/* This function can be modified to send data to a remote host.*/

	char mstr[QSTP_CONNECTION_MTU] = "ECHO: ";
	char rstr[QSTP_CONNECTION_MTU] = "RCVD #";
	uint8_t pmsg[QSTP_CONNECTION_MTU] = { 0 };
	qstp_network_packet pkt = { 0 };
	qsc_mutex mtx;
	size_t mlen;

	if (msglen > 0U)
	{
		mlen = qsc_stringutils_string_size(rstr);
		qsc_stringutils_int_to_string((int)cns->target.connection, rstr + mlen, sizeof(rstr) - mlen);
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), ": ");
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), message);

		mtx = qsc_async_mutex_lock_ex();
		server_print_message(rstr);
		qsc_async_mutex_unlock_ex(mtx);

		mlen = qsc_stringutils_concat_strings(mstr, sizeof(mstr), message);
		pkt.pmessage = pmsg;
		qstp_encrypt_packet(cns, &pkt, (uint8_t*)mstr, mlen);
		mlen = qstp_packet_to_stream(&pkt, (uint8_t*)mstr);
		qsc_socket_send(&cns->target, (const uint8_t*)mstr, mlen, qsc_socket_send_flag_none);
	}
}

static void server_disconnect_callback(qstp_connection_state* cns)
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_lock_ex();
	server_print_prompt();
	qsc_consoleutils_print_safe("The server has disconnected from host: ");
	qsc_consoleutils_print_line((const char*)cns->target.address);
	qsc_async_mutex_unlock_ex(mtx);
}

static void server_receive_callback(qstp_connection_state* cns, const char* message, size_t msglen)
{
	/* Envelope data in an application header, in a request->response model.
	   Parse that header here, process requests from the client, and transmit the response. */

	server_send_echo(cns, message, msglen);
}

int main(void)
{
	qsc_socket source = { 0 };
	qstp_errors qerr;

	qsc_memutils_clear(&m_server_signature_key, sizeof(qstp_server_signature_key));
	server_print_banner();

	if (server_key_dialogue() == true)
	{
		if (qstp_server_expiration_check(&m_server_signature_key) == true)
		{
			qsc_consoleutils_print_line("Waiting for a connection...");
			qerr = qstp_server_start_ipv4(&source, &m_server_signature_key, &server_receive_callback, &server_disconnect_callback);

			qsc_memutils_clear(&m_server_signature_key, sizeof(qstp_server_signature_key));

			if (qerr != qstp_error_none)
			{
				server_print_error(qerr);
				server_print_message("The network key-exchange failed, the application will exit.");
			}
		}
		else
		{
			server_print_message("The server key has expired, the application will exit.");
		}

		qstp_server_quit();
	}
	else
	{
		server_print_message("The signature key-pair could not be loaded, the application will exit.");
	}

	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
