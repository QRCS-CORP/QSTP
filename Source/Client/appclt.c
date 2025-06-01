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
 * Contact: john.underhill@protonmail.com
 */

#include "appclt.h"
#include "qstp.h"
#include "client.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe("client> ");
}

#if defined(QSTP_FUTURE_FEATURE)
static void client_print_error(qstp_errors error)
{
	const char* msg;

	msg = qstp_error_to_string(error);

	if (msg != NULL)
	{
		client_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}
#endif

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			client_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			client_print_prompt();
		}
	}
}

static void client_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0)
	{
		char* pmsg;

		pmsg = qsc_memutils_malloc(msglen + sizeof(char));

		if (pmsg != NULL)
		{
			qsc_memutils_clear(pmsg, msglen + sizeof(char));
			qsc_memutils_copy(pmsg, message, msglen);
			qsc_consoleutils_print_line(pmsg);
			qsc_memutils_alloc_free(pmsg);
		}
	}
}

static void client_print_banner(void)
{
	qsc_consoleutils_print_line("QSTP: Client Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Protocol client.");
	qsc_consoleutils_print_line("Enter the IP address and the server public key to connect.");
	qsc_consoleutils_print_line("Type 'qstp quit' to close the connection and exit the application.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.0.0.0a");
	qsc_consoleutils_print_line("Date:      August 1, 2024");
	qsc_consoleutils_print_line("Contact:   john.underhill@protonmail.com");
	qsc_consoleutils_print_line("");
}

static bool client_get_storage_path(char* fpath, size_t pathlen)
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
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_CLIENT_DIRECTORY_PATH);

		if (qsc_folderutils_directory_exists(fpath) == false)
		{
			res = qsc_folderutils_create_directory(fpath);
		}
	}

	return res;
}

static bool client_root_certificate_path(char* fpath, size_t pathlen)
{
	bool res;

	res = client_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_ROOT_PUBLIC_CERTIFICATE_NAME);
	}
	
	return res;
}

static bool client_root_certificate_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = client_root_certificate_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static bool client_server_certificate_path(char* fpath, size_t pathlen)
{
	bool res;

	res = client_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_SERVER_PUBLIC_CERTIFICATE_NAME);
	}
	
	return res;
}

#if defined(QSTP_FUTURE_FEATURE)
static bool client_server_certificate_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = client_server_certificate_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}
#endif

static bool client_ipv4_dialogue(qsc_ipinfo_ipv4_address* address, qstp_root_certificate* root, qstp_server_certificate* cert)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	char sadd[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t slen;
	bool res;

	res = false;

	client_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	client_print_message("");
	slen = qsc_consoleutils_get_formatted_line(sadd, sizeof(sadd));

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		qsc_ipinfo_ipv4_address addv4t = { 0 };

		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);

		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true && 
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, sizeof(addv4t.ipv4));
		}
		else
		{
			client_print_message("The address format is invalid.");
		}
	}
	else
	{
		client_print_message("The address format is invalid.");
	}

	if (res == true)
	{
		/* check for the root certificate */
		if (client_root_certificate_exists() == true)
		{
			char rpath[QSC_SYSTEM_MAX_PATH] = { 0 };

			client_root_certificate_path(rpath, sizeof(rpath));
			res = qstp_root_file_to_certificate(root, rpath);
		}
		else
		{
			client_print_message("Enter the path of the public root certificate:");
			client_print_message("");
			slen = qsc_consoleutils_get_line(fpath, sizeof(fpath));

			if (slen > 0 && 
				qsc_fileutils_exists(fpath) == true &&
				qsc_stringutils_string_contains(fpath, QSTP_ROOT_PUBLIC_CERTIFICATE_NAME) == true)
			{
				res = qstp_root_file_to_certificate(root, fpath);

				if (res == true)
				{
					char rpath[QSC_SYSTEM_MAX_PATH] = { 0 };

					client_root_certificate_path(rpath, sizeof(rpath));
					/* copy the root certificate to storage */
					res = qsc_fileutils_file_copy(fpath, rpath);
				}
				else
				{
					client_print_message("The root certificate is invalid.");
				}
			}
			else
			{
				res = false;
				client_print_message("The path is invalid or inaccessable.");
			}
		}
	}

	if (res == true)
	{
		/* load the server certificate */
		client_print_message("Enter the path of the public server certificate:");
		client_print_message("");
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath));

		if (slen > 0 && 
			qsc_fileutils_exists(fpath) == true &&
			qsc_stringutils_string_contains(fpath, QSTP_SERVER_CERTIFICATE_EXTENSION_NAME) == true)
		{
			res = qstp_server_file_to_certificate(cert, fpath);

			if (res == false)
			{
				client_print_message("The public certificate is invalid.");
			}
		}
		else
		{
			res = false;
			client_print_message("The path is invalid or inaccessable.");
		}
	}

	return res;
}

static void client_receive_callback(qstp_connection_state* cns, const char* pmsg, size_t msglen)
{
	(void)cns;
	client_print_string(pmsg, msglen);
	client_print_prompt();
}

static void client_send_loop(qstp_connection_state* cns)
{
	qstp_network_packet pkt = { 0 };
	uint8_t pmsg[QSTP_CONNECTION_MTU] = { 0 };
	uint8_t msgstr[QSTP_CONNECTION_MTU] = { 0 };
	char sin[QSTP_CONNECTION_MTU + 1] = { 0 };
	size_t mlen;

	mlen = 0;

	/* start the sender loop */
	while (true)
	{
		client_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "qstp quit"))
		{
			qstp_connection_close(cns, qstp_error_none, true);
			break;
		}
		else
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				pkt.pmessage = pmsg;
				qstp_encrypt_packet(cns, &pkt, (const uint8_t*)sin, mlen);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = qstp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

		if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
		{
			client_print_message("");
			mlen = 0;
		}
	}
}

int main(void)
{
	qstp_server_certificate cert = { 0 };
	qstp_root_certificate root = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t ectr;
	bool res;

	res = false;
	ectr = 0;
	client_print_banner();

	while (ectr < 3)
	{
		res = client_ipv4_dialogue(&addv4t, &root, &cert);

		if (res == true)
		{
			break;
		}

		++ectr;
	}

	if (res == true)
	{
		qstp_client_connect_ipv4(&root, &cert, &addv4t, QSTP_SERVER_PORT, &client_send_loop, &client_receive_callback);
	}
	else
	{
		client_print_message("Invalid input, exiting the application.");
		client_print_prompt();
	}

	qsc_consoleutils_print_line("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}
