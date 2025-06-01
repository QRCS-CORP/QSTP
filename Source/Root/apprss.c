#include "apprss.h"
#include "qstp.h"
#include "root.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "netutils.h"
#include "stringutils.h"

static qstp_root_signature_key m_root_signature_key;

static size_t root_extract_parameter(char* param, const char* command)
{
	const char* psub;
	size_t res;

	res = 0;
	psub = qsc_stringutils_reverse_sub_string(command, " ");

	if (psub != NULL)
	{
		res = qsc_stringutils_string_size(psub);

		if (res > 0)
		{
			qsc_memutils_copy(param, psub, res);
		}
	}

	return res;
}

static bool root_extract_parameters(char* param1, char* param2, const char* command)
{
	int64_t ilen;
	int64_t ipos;
	bool res;

	res = false;
	ipos = qsc_stringutils_find_string(command, " ") + 1;

	if (ipos > 0)
	{
		ilen = qsc_stringutils_find_string(command + ipos, ", ");

		if (ilen > 0)
		{
			size_t len;

			qsc_memutils_copy(param1, command + ipos, ilen);
			len = qsc_stringutils_string_size(command + ipos + ilen);

			if (len > 0)
			{
				qsc_memutils_copy(param2, command + ipos + ilen + 2, len);
				res = true;
			}
		}
	}

	return res;
}

static void root_print_prompt(void)
{
	qsc_consoleutils_print_safe("root> ");
}

static void root_print_error(qstp_errors error)
{
	const char* msg;

	msg = qstp_error_to_string(error);

	if (msg != NULL)
	{
		root_print_prompt();
		qsc_consoleutils_print_line(msg);
	}
}

static void root_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			root_print_prompt();
			qsc_consoleutils_print_line(message);
		}
		else
		{
			root_print_prompt();
		}
	}
}

static void root_print_banner(void)
{
	qsc_consoleutils_print_line("QSTP: Root Server Example Project");
	qsc_consoleutils_print_line("Quantum Secure Messaging Protocol root server.");
	qsc_consoleutils_print_line("Type 'quit' to exit the application, 'help' for command help.");
	qsc_consoleutils_print_line("");
	qsc_consoleutils_print_line("Release:   v1.1.0.0a (A1)");
	qsc_consoleutils_print_line("Date:      August 1, 2024");
	qsc_consoleutils_print_line("Contact:   john.underhill@protonmail.com");
	qsc_consoleutils_print_line("");
}

static void root_print_help(void)
{
	root_print_message("export [directory-path] -Export the public certificate.");
	root_print_message("generate [number-days] -Create a new root certificate.");
	root_print_message("help -Display the command help.");
	root_print_message("quit -Closes the application.");
	root_print_message("print -Print the root certificate to the console.");
	root_print_message("sprint [certificate-path] -Print a server certificate to the console.");
	root_print_message("sign [certificate-path] -Sign a child certificate.");
}

static bool root_get_storage_path(char* fpath, size_t pathlen)
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
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_ROOT_DIRECTORY_PATH);

		if (qsc_folderutils_directory_exists(fpath) == false)
		{
			res = qsc_folderutils_create_directory(fpath);
		}
	}

	return res;
}

static bool root_get_certificate_path(char* fpath, size_t pathlen)
{
	bool res;

	res = root_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_ROOT_PUBLIC_CERTIFICATE_NAME);
	}
	
	return res;
}

static bool root_get_key_path(char* fpath, size_t pathlen)
{
	bool res;

	res = root_get_storage_path(fpath, pathlen);

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, pathlen, QSTP_ROOT_PRIVATE_KEY_NAME);
	}

	return res;
}

static bool root_prikey_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = root_get_key_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

/* commands */

static bool root_certificate_export(const char* param)
{
	qstp_root_certificate root = { 0 };
	bool res;

	res = false;

	if (root_prikey_exists() == true)
	{
		if (qsc_folderutils_directory_exists(param) == true)
		{
			qstp_root_certificate_extract(&root, &m_root_signature_key);
			res = qstp_root_certificate_export(&root, param);
		}
	}

	return res;
}

static bool root_keyset_generate(const char* param, size_t plen)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = false;

	if (qsc_stringutils_is_numeric(param, plen) == true)
	{
		int32_t days;

		days = qsc_stringutils_string_to_int(param);

		if (days > 0)
		{
			root_get_certificate_path(fpath, sizeof(fpath));

			if (qsc_fileutils_exists(fpath) == true)
			{
				res = qsc_consoleutils_message_confirm("The certificate exists, do you want to overwrite it? Y | N");

				if (res == true)
				{
					qsc_fileutils_delete(fpath);
				}
			}
			else
			{
				res = true;
			}

			if (res == true)
			{
				qstp_root_certificate root = { 0 };
				char issuer[QSTP_CERTIFICATE_ISSUER_SIZE] = { 0 };

				/* Note: ex. mydomain_rds1.qrc */
				qstp_root_get_issuer(issuer);
				/* create the master key */
				qstp_root_key_generate(&m_root_signature_key, issuer, days);
				/* extract the root certificate and write to file */
				qstp_root_certificate_extract(&root, &m_root_signature_key);
				res = qstp_root_certificate_to_file(&root, fpath);

				if (res == true)
				{
					root_print_prompt();
					qsc_consoleutils_print_safe("The root certificate has been saved to: ");
					qsc_consoleutils_print_line(fpath);

					/* get the key state path */
					qsc_stringutils_clear_string(fpath);
					root_get_key_path(fpath, sizeof(fpath));
					/* copy the root key to file*/
					res = qstp_root_key_to_file(&m_root_signature_key, fpath);
				}
			}
		}
	}

	return res;
}

static bool root_certificate_print(void)
{
	qstp_root_certificate root = { 0 };
	bool res;

	res = root_prikey_exists();

	if (res == true)
	{
		qstp_root_certificate_extract(&root, &m_root_signature_key);
		qstp_root_certificate_print(&root);
	}

	return res;
}

static bool root_server_certificate_print(const char* param)
{
	qstp_server_certificate cert = { 0 };
	bool res;

	res = false;

	if (param != NULL)
	{
		if (qsc_stringutils_string_contains(param, QSTP_SERVER_CERTIFICATE_EXTENSION_NAME) == true &&
			qsc_fileutils_exists(param) == true)
		{
			if (qstp_server_file_to_certificate(&cert, param) == true)
			{
				qstp_root_server_certificate_print(&cert);
				res = true;
			}
		}
	}

	return res;
}

static bool root_certificate_sign(const char* param)
{
	assert(param != NULL);

	bool res;

	res = false;

	if (qsc_fileutils_exists(param) == true && 
		qsc_stringutils_string_contains(param, QSTP_SERVER_CERTIFICATE_EXTENSION_NAME) == true)
	{
		qstp_root_certificate root = { 0 };

		qstp_root_certificate_extract(&root, &m_root_signature_key); // TODO: move extract to implementation and pass cert in param
		res = qstp_root_sign_certificate(param, &root, m_root_signature_key.sigkey);
	}

	return res;
}

static bool root_key_dialogue(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = root_get_key_path(fpath, sizeof(fpath));

	if (res == true)
	{
		res = qsc_fileutils_exists(fpath);

		if (res == true)
		{
			res = qstp_root_file_to_key(&m_root_signature_key, fpath);

			if (res == false)
			{
				/* key is invalid, delete key and certificate */
				qsc_fileutils_delete(fpath);
				qsc_memutils_clear(fpath, sizeof(fpath));
				root_get_certificate_path(fpath, sizeof(fpath));

				if (qsc_fileutils_exists(fpath) == true)
				{
					qsc_fileutils_delete(fpath);
				}
			}
		}
	}

	if (res == true)
	{
		root_print_message("The root key has been loaded.");
	}
	else 
	{
		root_print_message("Root key not found, use the generate function to create a new key-set.");
	}

	return res;
}

static bool root_command_interpreter(const char* command)
{
	char param[QSC_SYSTEM_MAX_PATH] = { 0 };
	size_t plen;
	bool res;

	res = true;

	if (qsc_consoleutils_line_contains(command, "export ") == true)
	{
		plen = root_extract_parameter(param, command);

		if (plen > 0)
		{
			if (root_certificate_export(param) == true)
			{
				root_print_prompt();
				qsc_consoleutils_print_safe("The certificate has been exported to ");
				qsc_consoleutils_print_line(param);
			}
			else
			{
				root_print_message("The certificate could not be found, or the path is invalid.");
			}
		}
	}
	else if (qsc_consoleutils_line_contains(command, "generate ") == true)
	{
		plen = root_extract_parameter(param, command);

		if (plen > 0)
		{
			if (root_keyset_generate(param, plen) == false)
			{
				root_print_message("The public certificate and private key could not be created.");
			}
		}
	}
	else if (qsc_consoleutils_line_equals(command, "help") == true)
	{
		root_print_help();
	}
	else if (qsc_consoleutils_line_equals(command, "quit") == true)
	{
		res = false;
	}
	else if (qsc_consoleutils_line_equals(command, "print") == true)
	{
		if (root_certificate_print() == false)
		{
			root_print_message("The certificate could not be found.");
		}
	}
	else if (qsc_consoleutils_line_contains(command, "sprint ") == true)
	{
		plen = root_extract_parameter(param, command);

		if (plen > 0)
		{
			if (root_server_certificate_print(param) == false)
			{
				root_print_message("The certificate could not be found.");
			}
		}
	}
	else if (qsc_consoleutils_line_contains(command, "sign ") == true)
	{
		plen = root_extract_parameter(param, command);

		if (plen > 0)
		{
			if (root_certificate_sign(param) == true)
			{
				root_print_message("The certificate has been signed.");
			}
			else
			{
				root_print_message("The certificate could not be signed.");
			}
		}
	}
	else
	{
		if (qsc_stringutils_string_size(command) > 0)
		{
			root_print_message("The command is unrecognized, or the parameter is invalid.");
		}
	}

	return res;
}

static void root_command_loop(void)
{
	char cmd[QSC_CONSOLE_MAX_LINE] = { 0 };
	bool res;

	while (true)
	{
		root_print_prompt();
		qsc_consoleutils_get_line(cmd, QSC_CONSOLE_MAX_LINE);
		res = root_command_interpreter(cmd);

		if (res == false)
		{
			break;
		}
	}
}

int main(void)
{
	root_print_banner();
	qsc_memutils_clear(&m_root_signature_key, sizeof(qstp_root_signature_key));

	root_key_dialogue();
	root_command_loop();

	root_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}
