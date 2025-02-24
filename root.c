#include "root.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/async.h"
#include "../../QSC/QSC/consoleutils.h"
#include "../../QSC/QSC/fileutils.h"
#include "../../QSC/QSC/folderutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/socketclient.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

/** \cond */
#define ROOT_REVOKE_MESSAGE_SIZE (QSTP_ASYMMETRIC_SIGNATURE_SIZE + QSTP_CERTIFICATE_SERIAL_SIZE)
#define ROOT_REVOKE_PACKET_SIZE (QSTP_PACKET_HEADER_SIZE + ROOT_REVOKE_MESSAGE_SIZE)
/** \endcond */

/* root functions */

bool qstp_root_certificate_export(const qstp_root_certificate* root, const char* fpath)
{
	assert(root != NULL);
	assert(fpath != NULL);

	char cpath[QSTP_STORAGE_PATH_MAX] = { 0 };
	bool res;

	res = false;

	if (root != NULL && fpath != NULL)
	{
		if (qsc_folderutils_directory_exists(fpath) == true &&
			qsc_stringutils_string_size(root->issuer) > 0)
		{
			char scert[QSTP_ROOT_CERTIFICATE_SIZE] = { 0 };

			qsc_stringutils_copy_string(cpath, sizeof(cpath), fpath);

			if (qsc_folderutils_directory_has_delimiter(cpath) == false)
			{
				qsc_folderutils_append_delimiter(cpath);
			}

			qsc_stringutils_concat_strings(cpath, sizeof(cpath), root->issuer);

			res = qstp_root_certificate_to_file(root, cpath);
		}
	}

	return res;
}

void qstp_root_key_generate(qstp_root_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp)
{
	assert(kset != NULL);
	assert(exp != 0);

	if (kset != NULL && exp != 0)
	{
		uint64_t period;

		period = exp * 24 * 60 * 60;

		if (period >= QSTP_CERTIFICATE_MINIMUM_PERIOD || period <= QSTP_CERTIFICATE_MAXIMUM_PERIOD)
		{
			qsc_acp_generate(kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(kset->issuer, issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
			kset->expiration.from = qsc_timestamp_datetime_utc();
			kset->expiration.to = kset->expiration.from + period;
			kset->algorithm = QSTP_CONFIGURATION_SET;
			kset->version = (uint8_t)QSTP_ACTIVE_VERSION;
			qstp_signature_generate_keypair(kset->verkey, kset->sigkey, &qsc_acp_generate);
		}
	}
}

void qstp_root_certificate_print(const qstp_root_certificate* root)
{
	assert(root != NULL);

	char* penk;
	size_t elen;
	size_t slen;

	elen = qstp_root_certificate_encoded_size(root);
	penk = qsc_memutils_malloc(elen);

	if (penk != NULL)
	{
		qsc_memutils_clear(penk, elen);
		slen = qstp_root_certificate_encode(penk, elen, root);

		if (slen == elen)
		{
			qsc_consoleutils_print_safe(penk);
			qsc_consoleutils_print_line("");
		}

		qsc_memutils_alloc_free(penk);
	}
}

void qstp_root_server_certificate_print(const qstp_server_certificate* cert)
{
	assert(cert != NULL);

	char* penk;
	size_t elen;
	size_t slen;

	elen = qstp_server_certificate_encoded_size(cert);
	penk = qsc_memutils_malloc(elen);

	if (penk != NULL)
	{
		qsc_memutils_clear(penk, elen);
		slen = qstp_server_certificate_encode(penk, elen, cert);

		if (slen <= elen)
		{
			qsc_consoleutils_print_safe(penk);
			qsc_consoleutils_print_line("");
		}

		qsc_memutils_alloc_free(penk);
	}
}

bool qstp_root_sign_certificate(const char* fpath, const qstp_root_certificate* root, const uint8_t* rootkey)
{
	assert(fpath != NULL);
	assert(root != NULL);
	assert(rootkey != NULL);

	bool res;

	res = false;

	if (fpath != NULL && root != NULL && rootkey != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true &&
			qsc_stringutils_string_contains(fpath, QSTP_SERVER_CERTIFICATE_EXTENSION_NAME) == true)
		{
			qstp_server_certificate cert = { 0 };

			if (qstp_server_file_to_certificate(&cert, fpath) == true)
			{
				if (qstp_root_certificate_sign(&cert, root, rootkey) == QSTP_CERTIFICATE_SIGNED_HASH_SIZE)
				{
					res = qstp_server_certificate_to_file(&cert, fpath);
				}
			}
		}
	}

	return res;
}
