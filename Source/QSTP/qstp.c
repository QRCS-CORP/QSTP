#include "qstp.h"
#include "logger.h"
#include "async.h"
#include "acp.h"
#include "encoding.h"
#include "fileutils.h"
#include "intutils.h"
#include "memutils.h"
#include "netutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

qstp_configuration_sets qstp_configuration_from_string(const char* config)
{
	QSTP_ASSERT(config != NULL);

	size_t i;
	qstp_configuration_sets res;

	res = qstp_configuration_set_none;

	if (config != NULL)
	{
		for (i = 0U; i < QSTP_PROTOCOL_SET_DEPTH; ++i)
		{
			if (qsc_stringutils_string_contains(config, QSTP_PARAMETER_STRINGS[i]) == true)
			{
				res = (qstp_configuration_sets)i + 1U;
				break;
			}
		}
	}

	return res;
}

const char* qstp_configuration_to_string(qstp_configuration_sets cset)
{
	const char* cres;

	cres = NULL;

	if ((int)cset < QSTP_PROTOCOL_SET_DEPTH && (int)cset >= 0)
	{
		cres = QSTP_PARAMETER_STRINGS[(size_t)cset];
	}

	return cres;
}

void qstp_connection_close(qstp_connection_state* cns, qstp_errors err, bool notify)
{
	QSTP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				if (err == qstp_error_none)
				{
					qstp_network_packet resp = { 0 };
					uint8_t spct[QSTP_PACKET_HEADER_SIZE] = { 0U };

					/* send a disconnect message */
					resp.pmessage = spct + QSTP_PACKET_HEADER_SIZE;
					resp.flag = qstp_flag_connection_terminate;
					resp.sequence = QSTP_PACKET_SEQUENCE_TERMINATOR;
					resp.msglen = 0U;
					resp.pmessage = NULL;

					qstp_packet_header_serialize(&resp, spct);
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* send an error message */
					qstp_network_packet resp = { 0 };
					uint8_t perr[QSTP_PACKET_ERROR_SIZE] = { 0U };
					uint8_t* spct;
					size_t mlen;
					qstp_errors qerr;

					mlen = QSTP_PACKET_HEADER_SIZE + QSTP_PACKET_FLAG_SIZE + QSTP_MACTAG_SIZE;
					spct = (uint8_t*)qsc_memutils_malloc(mlen);

					if (spct != NULL)
					{
						qsc_memutils_clear(spct, mlen);

						/* send a disconnect message */
						resp.flag = qstp_flag_connection_terminate;
						resp.sequence = QSTP_PACKET_SEQUENCE_TERMINATOR;
						resp.msglen = QSTP_PACKET_ERROR_SIZE;
						resp.pmessage = spct + QSTP_PACKET_HEADER_SIZE;
						perr[0U] = err;

						qerr = qstp_encrypt_packet(cns, &resp, perr, QSTP_PACKET_ERROR_SIZE);

						if (qerr == qstp_error_none)
						{
							qstp_packet_header_serialize(&resp, spct);
							qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
						}

						qsc_memutils_alloc_free(spct);
					}
				}
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

void qstp_connection_state_dispose(qstp_connection_state* cns)
{
	QSTP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qstp_cipher_dispose(&cns->rxcpr);
		qstp_cipher_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		cns->rxseq = 0U;
		cns->txseq = 0U;
		cns->cid = 0U;
		cns->exflag = qstp_flag_none;
	}
}

qstp_errors qstp_decrypt_packet(qstp_connection_state* cns, uint8_t* message, size_t* msglen, const qstp_network_packet* packetin)
{
	QSTP_ASSERT(cns != NULL);
	QSTP_ASSERT(packetin != NULL);
	QSTP_ASSERT(message != NULL);
	QSTP_ASSERT(msglen != NULL);

	uint8_t hdr[QSTP_PACKET_HEADER_SIZE] = { 0U };
	qstp_errors qerr;

	qerr = qstp_error_invalid_input;
	*msglen = 0U;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		cns->rxseq += 1U;

		if (packetin->sequence == cns->rxseq)
		{
			if (cns->exflag == qstp_flag_session_established)
			{
				if (qstp_packet_time_valid(packetin) == true)
				{
					/* serialize the header and add it to the ciphers associated data */
					qstp_packet_header_serialize(packetin, hdr);

					qstp_cipher_set_associated(&cns->rxcpr, hdr, QSTP_PACKET_HEADER_SIZE);
					*msglen = packetin->msglen - QSTP_MACTAG_SIZE;

					/* authenticate then decrypt the data */
					if (qstp_cipher_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						qerr = qstp_error_none;
					}
					else
					{
						*msglen = 0U;
						qerr = qstp_error_authentication_failure;
					}
				}
				else
				{
					qerr = qstp_error_message_time_invalid;
				}
			}
			else
			{
				qerr = qstp_error_channel_down;
			}
		}
		else
		{
			qerr = qstp_error_packet_unsequenced;
		}
	}

	return qerr;
}

qstp_errors qstp_encrypt_packet(qstp_connection_state* cns, qstp_network_packet* packetout, const uint8_t* message, size_t msglen)
{
	QSTP_ASSERT(cns != NULL);
	QSTP_ASSERT(message != NULL);
	QSTP_ASSERT(packetout != NULL);

	qstp_errors qerr;

	qerr = qstp_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == qstp_flag_session_established && msglen != 0U)
		{
			uint8_t hdr[QSTP_PACKET_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			cns->txseq += 1U;
			qstp_header_create(packetout, qstp_flag_encrypted_message, cns->txseq, (uint32_t)msglen + QSTP_MACTAG_SIZE);

			/* serialize the header and add it to the ciphers associated data */
			qstp_packet_header_serialize(packetout, hdr);
			qstp_cipher_set_associated(&cns->txcpr, hdr, QSTP_PACKET_HEADER_SIZE);
			/* encrypt the message */
			qstp_cipher_transform(&cns->txcpr, packetout->pmessage, message, msglen);

			qerr = qstp_error_none;
		}
		else
		{
			qerr = qstp_error_channel_down;
		}
	}

	return qerr;
}

const char* qstp_error_to_string(qstp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((int)error < QSTP_ERROR_STRING_DEPTH && (int)error >= 0)
	{
		dsc = QSTP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

void qstp_header_create(qstp_network_packet* packetout, qstp_flags flag, uint64_t sequence, uint32_t msglen)
{
	QSTP_ASSERT(packetout != NULL);

	if (packetout != NULL)
	{
		packetout->flag = flag;
		packetout->sequence = sequence;
		packetout->msglen = msglen;
		/* set the packet creation time */
		qstp_packet_set_utc_time(packetout);
	}
}

qstp_errors qstp_header_validate(qstp_connection_state* cns, const qstp_network_packet* packetin, qstp_flags flag, uint64_t sequence, uint32_t msglen)
{
	QSTP_ASSERT(cns != NULL);
	QSTP_ASSERT(packetin != NULL);

	qstp_errors merr;

	merr = qstp_error_memory_allocation;

	if (cns != NULL && packetin != NULL)
	{
		if (packetin->flag == qstp_flag_error_condition)
		{
			merr = (qstp_errors)packetin->pmessage[0U];
		}
		else
		{
			if (qstp_packet_time_valid(packetin) == true)
			{
				if (packetin->msglen == msglen)
				{
					if (packetin->sequence == sequence)
					{
						if (packetin->flag == flag)
						{
							cns->rxseq += 1U;
							merr = qstp_error_none;
						}
						else
						{
							merr = qstp_error_invalid_request;
						}
					}
					else
					{
						merr = qstp_error_packet_unsequenced;
					}
				}
				else
				{
					merr = qstp_error_receive_failure;
				}
			}
			else
			{
				merr = qstp_error_message_time_invalid;
			}
		}
	}

	return merr;
}

void qstp_log_error(qstp_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	QSTP_ASSERT(msg != NULL);

	char mtmp[QSTP_ERROR_STRING_WIDTH * 2U] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = qstp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qstp_logger_write(mtmp);
		}
		else
		{
			qstp_logger_write(pmsg);
		}
	}

	phdr = qstp_get_error_description(qstp_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		qstp_logger_write(mtmp);
	}
}

void qstp_log_message(qstp_messages emsg)
{
	const char* msg = qstp_get_error_description(emsg);

	if (msg != NULL)
	{
		qstp_logger_write(msg);
	}
}

void qstp_log_write(qstp_messages emsg, const char* msg)
{
	QSTP_ASSERT(msg != NULL);

	const char* pmsg = qstp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[QSTP_ERROR_STRING_WIDTH] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			qstp_logger_write(mtmp);
		}
		else
		{
			qstp_logger_write(pmsg);
		}
	}
}

const char* qstp_get_error_description(qstp_messages message)
{
	const char* dsc;

	dsc = NULL;

	if ((int)message < QSTP_MESSAGE_STRING_DEPTH && (int)message >= 0)
	{
		dsc = QSTP_MESSAGE_STRINGS[(size_t)message];

	}

	return dsc;
}

void qstp_packet_clear(qstp_network_packet* packet)
{
	QSTP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		if (packet->msglen != 0U)
		{
			qsc_memutils_clear(packet->pmessage, packet->msglen);
		}

		packet->flag = (uint8_t)qstp_flag_none;
		packet->msglen = 0U;
		packet->sequence = 0U;
		packet->utctime = 0U;
	}
}

void qstp_packet_error_message(qstp_network_packet* packet, qstp_errors error)
{
	QSTP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = qstp_flag_error_condition;
		packet->msglen = QSTP_PACKET_ERROR_SIZE;
		packet->sequence = QSTP_PACKET_ERROR_SEQUENCE;
		packet->pmessage[0U] = (uint8_t)error;
		qstp_packet_set_utc_time(packet);
	}
}

void qstp_packet_header_deserialize(const uint8_t* header, qstp_network_packet* packet)
{
	QSTP_ASSERT(header != NULL);
	QSTP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		packet->flag = header[0U];
		pos = QSTP_PACKET_FLAG_SIZE;
		packet->msglen = qsc_intutils_le8to32(header + pos);
		pos += QSTP_PACKET_MESSAGE_LENGTH_SIZE;
		packet->sequence = qsc_intutils_le8to64(header + pos);
		pos += QSTP_PACKET_SEQUENCE_SIZE;
		packet->utctime = qsc_intutils_le8to64(header + pos);
	}
}

void qstp_packet_header_serialize(const qstp_network_packet* packet, uint8_t* header)
{
	QSTP_ASSERT(header != NULL);
	QSTP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		size_t pos;

		header[0U] = packet->flag;
		pos = QSTP_PACKET_FLAG_SIZE;
		qsc_intutils_le32to8(header + pos, packet->msglen);
		pos += QSTP_PACKET_MESSAGE_LENGTH_SIZE;
		qsc_intutils_le64to8(header + pos, packet->sequence);
		pos += QSTP_PACKET_SEQUENCE_SIZE;
		qsc_intutils_le64to8(header + pos, packet->utctime);
	}
}

void qstp_packet_set_utc_time(qstp_network_packet* packet)
{
	QSTP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->utctime = qsc_timestamp_datetime_utc();
	}
}

bool qstp_packet_time_valid(const qstp_network_packet* packet)
{
	QSTP_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();
		/* two-way variance to account for differences in system clocks */
		res = (ltime >= packet->utctime - QSTP_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + QSTP_PACKET_TIME_THRESHOLD);
	}

	return res;
}

size_t qstp_packet_to_stream(const qstp_network_packet* packet, uint8_t* pstream)
{
	QSTP_ASSERT(packet != NULL);
	QSTP_ASSERT(pstream != NULL);

	size_t pos;
	size_t res;

	res = 0U;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		pos = QSTP_PACKET_FLAG_SIZE;
		qsc_intutils_le32to8(pstream + pos, packet->msglen);
		pos += QSTP_PACKET_MESSAGE_LENGTH_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->sequence);
		pos += QSTP_PACKET_SEQUENCE_SIZE;
		qsc_intutils_le64to8(pstream + pos, packet->utctime);
		pos += QSTP_CERTIFICATE_TIMESTAMP_SIZE;
		qsc_memutils_copy(pstream + pos, packet->pmessage, packet->msglen);
		res = (size_t)QSTP_PACKET_HEADER_SIZE + packet->msglen;
	}

	return res;
}

bool qstp_root_certificate_compare(const qstp_root_certificate* a, const qstp_root_certificate* b)
{
	QSTP_ASSERT(a != NULL);
	QSTP_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && 
			a->version == b->version &&
			a->expiration.from == b->expiration.from && 
			a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, QSTP_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, QSTP_CERTIFICATE_SERIAL_SIZE) == true)
				{
					res = qsc_memutils_are_equal(a->verkey, b->verkey, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
				}
			}
		}
	}

	return res;
}

bool qstp_root_certificate_decode(qstp_root_certificate* root, const char* enck, size_t enclen)
{
	QSTP_ASSERT(root != NULL);
	QSTP_ASSERT(enck != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char prot[QSTP_PROTOCOL_SET_SIZE] = { 0 };
	char vers[QSTP_ROOT_ACTIVE_VERSION_STRING_SIZE] = { 0 };
	char* pvk;
	size_t elen;
	size_t slen;
	size_t spos;
	bool res;

	res = false;

	if (root != NULL && enck != NULL)
	{
		spos = sizeof(QSTP_ROOT_CERTIFICATE_HEADER) - 1U;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX) - 1U;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(root->issuer, enck + spos, slen);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX) - 1U;
		slen = QSTP_CERTIFICATE_SERIAL_SIZE * 2U;
		qsc_intutils_hex_to_bin(enck + spos, root->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		root->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		root->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_PROTOCOL_PREFIX) - 1U;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(prot, enck + spos, slen);
		root->algorithm = qstp_configuration_from_string(prot);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_VERSION_PREFIX) - 1U;
		slen = sizeof(QSTP_ACTIVE_VERSION_STRING) - 1U;
		qsc_memutils_copy(vers, enck + spos, slen);
		root->version = qstp_version_from_string(vers + QSC_STRINGUTILS_HEX_EXTENSION_SIZE, QSC_STRINGUTILS_HEX_BYTE_SIZE);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) - 1U;
		elen = qsc_encoding_base64_encoded_size(QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pvk = qsc_memutils_malloc(elen);

		if (pvk != NULL)
		{
			qsc_memutils_clear(pvk, elen);
			elen = qsc_stringutils_remove_line_breaks(pvk, elen, enck + spos, enclen - spos);
			res = qsc_encoding_base64_decode(root->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE, pvk, elen);
			qsc_memutils_alloc_free(pvk);
		}
	}

	return res;
}

void qstp_root_certificate_deserialize(qstp_root_certificate* root, const uint8_t input[QSTP_ROOT_CERTIFICATE_SIZE])
{
	QSTP_ASSERT(root != NULL);

	size_t pos;

	if (root != NULL)
	{
		qsc_memutils_copy(root->verkey, input, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(root->issuer, input + pos, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos += QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(root->serial, input + pos, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		root->expiration.from = qsc_intutils_le8to64(input + pos);
		root->expiration.to = qsc_intutils_le8to64(input + pos + sizeof(uint64_t));
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&root->algorithm, input + pos, sizeof(uint8_t));
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(&root->version, input + pos, sizeof(uint8_t));
	}
}

size_t qstp_root_certificate_encoded_size(void)
{
	size_t elen;
	size_t klen;

	elen = sizeof(QSTP_ROOT_CERTIFICATE_HEADER) - 1U;
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX) - 1U;
	elen += QSTP_CERTIFICATE_ISSUER_SIZE;
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX) - 1U;
	elen += (QSTP_CERTIFICATE_SERIAL_SIZE * 2U);
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX) - 1U;
	elen += QSC_TIMESTAMP_STRING_SIZE;
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
	elen += QSC_TIMESTAMP_STRING_SIZE;
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_PROTOCOL_PREFIX) - 1U;
	elen += sizeof(QSTP_PROTOCOL_SET_STRING);
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_VERSION_PREFIX) - 1U;
	elen += sizeof(QSTP_ACTIVE_VERSION_STRING);
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) - 1U;
	++elen;
	klen = qsc_encoding_base64_encoded_size(QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	elen += klen + (klen / QSTP_CERTIFICATE_LINE_LENGTH) + 1U;
	++elen;
	elen += sizeof(QSTP_ROOT_CERTIFICATE_FOOTER);
	++elen;
	++elen;

	return elen;
}

size_t qstp_root_certificate_encode(char* enck, size_t enclen, const qstp_root_certificate* root)
{
	QSTP_ASSERT(enck != NULL);
	QSTP_ASSERT(root != NULL);

	char* prvs;
	size_t elen;
	size_t slen;
	size_t spos;

	spos = 0U;

	if (enck != NULL && root != NULL)
	{
		char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
		char hex[(QSTP_CERTIFICATE_SERIAL_SIZE * 2U) + 1U] = { 0 };

		slen = sizeof(QSTP_ROOT_CERTIFICATE_HEADER) - 1U;
		qsc_memutils_copy(enck, QSTP_ROOT_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(root->issuer);
		qsc_memutils_copy(enck + spos, root->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(root->serial, hex, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hex);
		slen = qsc_stringutils_string_size(hex);
		qsc_memutils_copy(enck + spos, hex, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.from, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(root->expiration.to, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_PROTOCOL_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_PROTOCOL_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(QSTP_PROTOCOL_SET_STRING);
		qsc_memutils_copy(enck + spos, QSTP_PROTOCOL_SET_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_VERSION_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSTP_ACTIVE_VERSION_STRING) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ACTIVE_VERSION_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		prvs = qsc_memutils_malloc(elen);

		if (prvs != NULL)
		{
			qsc_memutils_clear(prvs, elen);
			qsc_encoding_base64_encode(prvs, elen, root->verkey, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSTP_CERTIFICATE_LINE_LENGTH, prvs, elen);
			qsc_memutils_alloc_free(prvs);
		}

		slen = sizeof(QSTP_ROOT_CERTIFICATE_FOOTER) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ROOT_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
		enck[spos] = 0U;
		++spos;
	}

	return spos;
}

void qstp_root_certificate_extract(qstp_root_certificate* root, const qstp_root_signature_key* kset)
{
	QSTP_ASSERT(root != NULL);
	QSTP_ASSERT(kset != NULL);

	if (root != NULL && kset != NULL)
	{
		qsc_memutils_copy(root->issuer, kset->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(root->serial, kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(root->verkey, kset->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		root->expiration.from = kset->expiration.from;
		root->expiration.to = kset->expiration.to;
		root->algorithm = kset->algorithm;
		root->version = kset->version;
	}
}

void qstp_root_certificate_hash(uint8_t output[QSTP_CERTIFICATE_HASH_SIZE], const qstp_root_certificate* root)
{
	QSTP_ASSERT(root != NULL);

	qsc_keccak_state kstate = { 0 };
	uint8_t nbuf[sizeof(uint64_t)] = { 0U };

	if (root != NULL)
	{
		qsc_sha3_initialize(&kstate);
		nbuf[0U] = root->algorithm;
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = root->version;
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, root->expiration.from);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, root->expiration.to);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)root->issuer, qsc_stringutils_string_size(root->issuer));
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, root->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, root->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, output);
	}
}

void qstp_root_certificate_serialize(uint8_t output[QSTP_ROOT_CERTIFICATE_SIZE], const qstp_root_certificate* root)
{
	QSTP_ASSERT(root != NULL);

	size_t pos;

	if (root != NULL)
	{
		qsc_memutils_copy(output, root->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos = QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, root->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos += QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, root->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_intutils_le64to8(output + pos, root->expiration.from);
		qsc_intutils_le64to8(output + pos + sizeof(uint64_t), root->expiration.to);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &root->algorithm, sizeof(uint8_t));
		pos += sizeof(uint8_t);
		qsc_memutils_copy(output + pos, &root->version, sizeof(uint8_t));
	}
}

size_t qstp_root_certificate_sign(qstp_server_certificate* cert, const qstp_root_certificate* root, const uint8_t* rsigkey)
{
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(root != NULL);
	QSTP_ASSERT(rsigkey != NULL);

	uint8_t hash[QSTP_CERTIFICATE_HASH_SIZE] = { 0U };
	size_t slen;

	slen = 0;

	if (cert != NULL && root != NULL && rsigkey != NULL)
	{
		if (cert->expiration.to > root->expiration.to)
		{
			cert->expiration.to = root->expiration.to;
		}

		qsc_memutils_copy(cert->rootser, root->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qstp_server_certificate_hash(hash, cert);
		qstp_signature_sign(cert->csig, &slen, hash, sizeof(hash), rsigkey, qsc_acp_generate);
	}

	return slen;
}

bool qstp_root_certificate_verify(const qstp_root_certificate* root, const qstp_server_certificate* cert)
{
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(root != NULL);

	size_t mlen;
	bool res;

	res = false;
	mlen = 0U;

	if (cert != NULL && root != NULL)
	{
		uint8_t msg[QSTP_CERTIFICATE_HASH_SIZE] = { 0U };

		res = qstp_signature_verify(msg, &mlen, cert->csig, QSTP_CERTIFICATE_SIGNED_HASH_SIZE, root->verkey);

		if (res == true)
		{
			uint8_t hash[QSTP_CERTIFICATE_HASH_SIZE] = { 0U };

			qstp_server_certificate_hash(hash, cert);

			res = qsc_memutils_are_equal(msg, hash, QSTP_CERTIFICATE_HASH_SIZE);
		}
	}

	return res;
}

bool qstp_root_certificate_to_file(const qstp_root_certificate* root, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(root != NULL);

	uint8_t sroot[QSTP_ROOT_CERTIFICATE_SIZE] = { 0U };
	bool res;

	res = false;

	if (fpath != NULL && root != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		qstp_root_certificate_serialize(sroot, root);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)sroot, sizeof(sroot));
	}

	return res;
}

bool qstp_root_file_to_certificate(qstp_root_certificate* root, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(root != NULL);

	bool res;

	res = false;

	if (fpath != NULL && root != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t sroot[QSTP_ROOT_CERTIFICATE_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)sroot, QSTP_ROOT_CERTIFICATE_SIZE) == QSTP_ROOT_CERTIFICATE_SIZE)
			{
				qstp_root_certificate_deserialize(root, sroot);
				res = true;
			}
		}
	}

	return res;
}

bool qstp_root_file_to_key(qstp_root_signature_key* kset, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(kset != NULL);

	bool res;

	res = false;

	if (fpath != NULL && kset != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t skset[QSTP_ROOT_SIGNATURE_KEY_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)skset, QSTP_ROOT_SIGNATURE_KEY_SIZE) == QSTP_ROOT_SIGNATURE_KEY_SIZE)
			{
				qstp_root_key_deserialize(kset, skset);
				res = true;
			}
		}
	}

	return res;
}

void qstp_root_get_issuer(char issuer[QSTP_CERTIFICATE_ISSUER_SIZE])
{
	char domain[QSC_NETUTILS_DOMAIN_NAME_SIZE] = { 0 };
	char host[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };

	qsc_netutils_get_host_name(host);
	qsc_netutils_get_domain_name(domain);

	/* use the default domain name if domain not present */
	if (qsc_stringutils_string_contains(domain, host) == true)
	{
		qsc_stringutils_clear_string(domain);
		qsc_stringutils_copy_string(domain, QSC_NETUTILS_DOMAIN_NAME_SIZE, QSTP_CERTIFICATE_DEFAULT_DOMAIN);
	}

	qsc_memutils_clear(issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, domain);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, "_");
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, host);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, QSTP_ROOT_CERTIFICATE_EXTENSION_NAME);
}

void qstp_root_key_deserialize(qstp_root_signature_key* kset, const uint8_t input[QSTP_ROOT_SIGNATURE_KEY_SIZE])
{
	QSTP_ASSERT(kset != NULL);

	size_t pos;

	if (kset != NULL)
	{
		qsc_memutils_copy(kset->issuer, input, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos = QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(kset->serial, input + pos, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(kset->sigkey, input + pos, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(kset->verkey, input + pos, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(&kset->expiration, input + pos, QSTP_CERTIFICATE_EXPIRATION_SIZE);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		kset->algorithm = input[pos];
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		kset->version = input[pos];
	}
}

bool qstp_root_key_to_file(const qstp_root_signature_key* kset, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(kset != NULL);

	uint8_t skset[QSTP_ROOT_SIGNATURE_KEY_SIZE] = { 0U };
	bool res;

	res = false;

	if (fpath != NULL && kset != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		qstp_root_key_serialize(skset, kset);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)skset, QSTP_ROOT_SIGNATURE_KEY_SIZE);
	}

	return res;
}

void qstp_root_key_serialize(uint8_t output[QSTP_ROOT_SIGNATURE_KEY_SIZE], const qstp_root_signature_key* kset)
{
	QSTP_ASSERT(kset != NULL);

	size_t pos;

	if (kset != NULL)
	{
		qsc_memutils_copy(output, kset->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos = QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, kset->sigkey, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(output + pos, kset->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_intutils_le64to8(output + pos, kset->expiration.from);
		qsc_intutils_le64to8(output + pos + sizeof(uint64_t), kset->expiration.to);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		output[pos] = kset->algorithm;
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		output[pos] = kset->version;
	}
}

bool qstp_server_certificate_compare(const qstp_server_certificate* a, const qstp_server_certificate* b)
{
	QSTP_ASSERT(a != NULL);
	QSTP_ASSERT(b != NULL);

	bool res;

	res = false;

	if (a != NULL && b != NULL)
	{
		if (a->algorithm == b->algorithm && 
			a->version == b->version && 
			a->expiration.from == b->expiration.from && 
			a->expiration.to == b->expiration.to)
		{
			if (qsc_memutils_are_equal((const uint8_t*)a->issuer, (const uint8_t*)b->issuer, QSTP_CERTIFICATE_ISSUER_SIZE) == true)
			{
				if (qsc_memutils_are_equal(a->serial, b->serial, QSTP_CERTIFICATE_SERIAL_SIZE) == true)
				{
					if (qsc_memutils_are_equal(a->csig, b->csig, QSTP_CERTIFICATE_SIGNED_HASH_SIZE) == true)
					{
						if (qsc_memutils_are_equal(a->rootser, b->rootser, QSTP_CERTIFICATE_SERIAL_SIZE) == true)
						{
							res = qsc_memutils_are_equal(a->verkey, b->verkey, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
						}
					}
				}
			}
		}
	}

	return res;
}

bool qstp_server_certificate_decode(qstp_server_certificate* cert, const char* enck, size_t enclen)
{
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(enck != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char prot[QSTP_PROTOCOL_SET_SIZE] = { 0 };
	char vers[QSTP_ROOT_ACTIVE_VERSION_STRING_SIZE] = { 0 };
	char* pcs;
	char* pvk;
	size_t elen;
	size_t slen;
	size_t spos;
	bool res;

	res = false;

	if (cert != NULL && enck != NULL)
	{
		spos = sizeof(QSTP_CHILD_CERTIFICATE_HEADER) - 1U;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX) - 1U;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(cert->issuer, enck + spos, slen);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX) - 1U;
		slen = QSTP_CERTIFICATE_SERIAL_SIZE * 2U;
		qsc_intutils_hex_to_bin(enck + spos, cert->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		cert->expiration.from = qsc_timestamp_datetime_to_seconds(dtm);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(dtm, enck + spos, slen);
		cert->expiration.to = qsc_timestamp_datetime_to_seconds(dtm);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_PROTOCOL_PREFIX) - 1U;
		slen = qsc_stringutils_find_char(enck + spos, '\n');
		qsc_memutils_copy(prot, enck + spos, slen);
		cert->algorithm = qstp_configuration_from_string(prot);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_VERSION_PREFIX) - 1U;
		slen = sizeof(QSTP_ACTIVE_VERSION_STRING) - 1U;
		qsc_memutils_copy(vers, enck + spos, slen);
		cert->version = qstp_version_from_string(vers + QSC_STRINGUTILS_HEX_EXTENSION_SIZE, QSC_STRINGUTILS_HEX_BYTE_SIZE);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX) - 1U;
		slen = QSTP_CERTIFICATE_SERIAL_SIZE * 2U;
		qsc_intutils_hex_to_bin(enck + spos, cert->rootser, QSTP_CERTIFICATE_SERIAL_SIZE);
		spos += slen;
		++spos;

		spos += sizeof(QSTP_CHILD_CERTIFICATE_ROOT_HASH_PREFIX) - 1U;
		++spos;
		elen = qsc_encoding_base64_encoded_size(QSTP_CERTIFICATE_SIGNED_HASH_SIZE);
		pcs = qsc_memutils_malloc(elen);

		if (pcs != NULL)
		{
			qsc_memutils_clear(pcs, elen);
			qsc_stringutils_remove_line_breaks(pcs, elen, enck + spos, enclen - spos);
			spos += elen;
			spos += (elen / QSTP_CERTIFICATE_LINE_LENGTH) + 1U;
			res = qsc_encoding_base64_decode(cert->csig, QSTP_CERTIFICATE_SIGNED_HASH_SIZE, pcs, elen);
			qsc_memutils_alloc_free(pcs);
		}

		if (res == true)
		{
			spos += sizeof(QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX) - 1U;
			++spos;
			elen = qsc_encoding_base64_encoded_size(QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
			pvk = qsc_memutils_malloc(elen);

			if (pvk != NULL)
			{
				qsc_memutils_clear(pvk, elen);
				elen = qsc_stringutils_remove_line_breaks(pvk, elen, enck + spos, enclen - spos);
				res = qsc_encoding_base64_decode(cert->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE, pvk, elen);
				qsc_memutils_alloc_free(pvk);
			}
		}
	}

	return res;
}

void qstp_server_certificate_deserialize(qstp_server_certificate* cert, const uint8_t input[QSTP_SERVER_CERTIFICATE_SIZE])
{
	QSTP_ASSERT(cert != NULL);

	size_t pos;

	if (cert != NULL)
	{
		qsc_memutils_copy(cert->csig, input, QSTP_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = QSTP_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(cert->verkey, input + pos, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(cert->issuer, input + pos, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos += QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(cert->serial, input + pos, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(cert->rootser, input + pos, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		cert->expiration.from = qsc_intutils_le8to64(input + pos);
		cert->expiration.to = qsc_intutils_le8to64(input + pos + sizeof(uint64_t));
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(&cert->algorithm, input + pos, QSTP_CERTIFICATE_ALGORITHM_SIZE);
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(&cert->version, input + pos, QSTP_CERTIFICATE_VERSION_SIZE);
	}
}

size_t qstp_server_certificate_encoded_size(void)
{
	size_t elen;
	size_t klen;

	elen = sizeof(QSTP_CHILD_CERTIFICATE_HEADER);
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX);
	elen += QSTP_CERTIFICATE_ISSUER_SIZE;
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX);
	elen += (QSTP_CERTIFICATE_SERIAL_SIZE * 2U);
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX);
	elen += QSC_TIMESTAMP_STRING_SIZE - 1U;
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX);
	elen += QSC_TIMESTAMP_STRING_SIZE - 1U;
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_PROTOCOL_PREFIX);
	elen += sizeof(QSTP_PROTOCOL_SET_STRING);
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_VERSION_PREFIX);
	elen += sizeof(QSTP_ACTIVE_VERSION_STRING);
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX);
	elen += (QSTP_CERTIFICATE_SERIAL_SIZE * 2U);
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_ROOT_HASH_PREFIX);
	++elen;
	klen = qsc_encoding_base64_encoded_size(QSTP_CERTIFICATE_SIGNED_HASH_SIZE);
	elen += klen + (klen / QSTP_CERTIFICATE_LINE_LENGTH) + 1U;
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX);
	klen = qsc_encoding_base64_encoded_size(QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	elen += klen + (klen / QSTP_CERTIFICATE_LINE_LENGTH) + 1U;
	++elen;
	elen += sizeof(QSTP_CHILD_CERTIFICATE_FOOTER);
	++elen;
	++elen;

	return elen;
}

size_t qstp_server_certificate_encode(char* enck, size_t enclen, const qstp_server_certificate* cert)
{
	QSTP_ASSERT(enck != NULL);
	QSTP_ASSERT(cert != NULL);

	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char hex[(QSTP_CERTIFICATE_SERIAL_SIZE * 2U) + 1U] = { 0 };
	char* psig;
	char* pver;
	size_t elen;
	size_t slen;
	size_t spos;

	spos = 0;

	if (enck != NULL && cert != NULL)
	{
		slen = sizeof(QSTP_CHILD_CERTIFICATE_HEADER) - 1U;
		qsc_memutils_copy(enck, QSTP_CHILD_CERTIFICATE_HEADER, slen);
		spos = slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(cert->issuer);
		qsc_memutils_copy(enck + spos, cert->issuer, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(cert->serial, hex, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hex);
		slen = qsc_stringutils_string_size(hex);
		qsc_memutils_copy(enck + spos, hex, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(cert->expiration.from, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX, slen);
		spos += slen;
		qsc_timestamp_seconds_to_datetime(cert->expiration.to, dtm);
		slen = QSC_TIMESTAMP_STRING_SIZE - 1U;
		qsc_memutils_copy(enck + spos, dtm, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_PROTOCOL_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_PROTOCOL_PREFIX, slen);
		spos += slen;
		slen = qsc_stringutils_string_size(QSTP_PROTOCOL_SET_STRING);
		qsc_memutils_copy(enck + spos, QSTP_PROTOCOL_SET_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_VERSION_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_VERSION_PREFIX, slen);
		spos += slen;
		slen = sizeof(QSTP_ACTIVE_VERSION_STRING) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_ACTIVE_VERSION_STRING, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX, slen);
		spos += slen;
		qsc_intutils_bin_to_hex(cert->rootser, hex, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_stringutils_to_uppercase(hex);
		slen = qsc_stringutils_string_size(hex);
		qsc_memutils_copy(enck + spos, hex, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = sizeof(QSTP_CHILD_CERTIFICATE_ROOT_HASH_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_ROOT_HASH_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSTP_CERTIFICATE_SIGNED_HASH_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		psig = qsc_memutils_malloc(elen);

		if (psig != NULL)
		{
			qsc_memutils_clear(psig, elen);
			qsc_encoding_base64_encode(psig, elen, cert->csig, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSTP_CERTIFICATE_LINE_LENGTH, psig, elen);
			qsc_memutils_alloc_free(psig);
			enck[spos] = '\n';
			++spos;
		}

		slen = sizeof(QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;

		slen = QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		elen = qsc_encoding_base64_encoded_size(slen);
		pver = qsc_memutils_malloc(elen);

		if (pver != NULL)
		{
			qsc_memutils_clear(pver, elen);
			qsc_encoding_base64_encode(pver, elen, cert->verkey, slen);
			spos += qsc_stringutils_add_line_breaks(enck + spos, enclen - spos, QSTP_CERTIFICATE_LINE_LENGTH, pver, elen);
			qsc_memutils_alloc_free(pver);
		}

		slen = sizeof(QSTP_CHILD_CERTIFICATE_FOOTER) - 1U;
		qsc_memutils_copy(enck + spos, QSTP_CHILD_CERTIFICATE_FOOTER, slen);
		spos += slen;
		enck[spos] = '\n';
		++spos;
		enck[spos] = 0;
		++spos;
	}

	return spos;
}

void qstp_server_certificate_extract(qstp_server_certificate* cert, const qstp_server_signature_key* kset)
{
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(kset != NULL);

	if (cert != NULL && kset != NULL)
	{
		qsc_memutils_copy(cert->issuer, kset->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		qsc_memutils_copy(cert->serial, kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_copy(cert->verkey, kset->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		cert->expiration.from = kset->expiration.from;
		cert->expiration.to = kset->expiration.to;
		cert->algorithm = kset->algorithm;
		cert->version = kset->version;
	}
}

void qstp_server_certificate_hash(uint8_t output[QSTP_CERTIFICATE_HASH_SIZE], const qstp_server_certificate* cert)
{
	QSTP_ASSERT(cert != NULL);

	qsc_keccak_state kstate = { 0 };
	uint8_t nbuf[sizeof(uint64_t)] = { 0U };

	if (cert != NULL)
	{
		qsc_sha3_initialize(&kstate);
		nbuf[0U] = cert->algorithm;
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		nbuf[0U] = cert->version;
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint8_t));
		qsc_intutils_le64to8(nbuf, cert->expiration.from);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_intutils_le64to8(nbuf, cert->expiration.to);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, nbuf, sizeof(uint64_t));
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, (const uint8_t*)cert->issuer, qsc_stringutils_string_size((const char*)cert->issuer));
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, cert->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_sha3_update(&kstate, qsc_keccak_rate_256, cert->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, output);
	}
}

void qstp_server_root_certificate_hash(uint8_t rshash[QSTP_CERTIFICATE_HASH_SIZE], const qstp_root_certificate* root, const qstp_server_certificate* cert)
{
	qsc_keccak_state kstate = { 0 };
	uint8_t rhash[QSTP_CERTIFICATE_HASH_SIZE] = { 0U };
	uint8_t shash[QSTP_CERTIFICATE_HASH_SIZE] = { 0U };

	qstp_root_certificate_hash(rhash, root);
	qstp_server_certificate_hash(shash, cert);

	qsc_sha3_initialize(&kstate);
	qsc_sha3_update(&kstate, qsc_keccak_rate_256, rhash, QSTP_CERTIFICATE_HASH_SIZE);
	qsc_sha3_update(&kstate, qsc_keccak_rate_256, shash, QSTP_CERTIFICATE_HASH_SIZE);
	qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, rshash);
	qsc_keccak_dispose(&kstate);

}

void qstp_server_certificate_serialize(uint8_t output[QSTP_SERVER_CERTIFICATE_SIZE], const qstp_server_certificate* cert)
{
	QSTP_ASSERT(cert != NULL);

	size_t pos;

	if (cert != NULL)
	{
		qsc_memutils_copy(output, cert->csig, QSTP_CERTIFICATE_SIGNED_HASH_SIZE);
		pos = QSTP_CERTIFICATE_SIGNED_HASH_SIZE;
		qsc_memutils_copy(output + pos, cert->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(output + pos, cert->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos += QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, cert->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, cert->rootser, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_intutils_le64to8(output + pos, cert->expiration.from);
		qsc_intutils_le64to8(output + pos + sizeof(uint64_t), cert->expiration.to);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, &cert->algorithm, QSTP_CERTIFICATE_ALGORITHM_SIZE);
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		qsc_memutils_copy(output + pos, &cert->version, QSTP_CERTIFICATE_VERSION_SIZE);
		pos += QSTP_CERTIFICATE_VERSION_SIZE;
	}
}

bool qstp_server_certificate_to_file(const qstp_server_certificate* cert, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(cert != NULL);

	uint8_t scert[QSTP_SERVER_CERTIFICATE_SIZE] = { 0U };
	bool res;

	res = false;

	if (fpath != NULL && cert != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		qstp_server_certificate_serialize(scert, cert);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)scert, QSTP_SERVER_CERTIFICATE_SIZE);
	}

	return res;
}

bool qstp_server_file_to_certificate(qstp_server_certificate* cert, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(cert != NULL);

	bool res;

	res = false;

	if (fpath != NULL && cert != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t scert[QSTP_SERVER_CERTIFICATE_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)scert, QSTP_SERVER_CERTIFICATE_SIZE) == QSTP_SERVER_CERTIFICATE_SIZE)
			{
				qstp_server_certificate_deserialize(cert, scert);
				res = true;
			}
		}
	}

	return res;
}

bool qstp_server_file_to_key(qstp_server_signature_key* kset, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(kset != NULL);

	bool res;

	res = false;

	if (fpath != NULL && kset != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			uint8_t skset[QSTP_SERVER_SIGNATURE_KEY_SIZE] = { 0U };

			if (qsc_fileutils_copy_file_to_stream(fpath, (char*)skset, QSTP_SERVER_SIGNATURE_KEY_SIZE) == QSTP_SERVER_SIGNATURE_KEY_SIZE)
			{
				qstp_server_key_deserialize(kset, skset);
				res = true;
			}
		}
	}

	return res;
}

void qstp_server_get_issuer(char issuer[QSTP_CERTIFICATE_ISSUER_SIZE])
{
	char domain[QSC_NETUTILS_DOMAIN_NAME_SIZE] = { 0 };
	char host[QSC_NETUTILS_HOSTS_NAME_SIZE] = { 0 };

	qsc_netutils_get_domain_name(domain);
	qsc_netutils_get_host_name(host);

	if (qsc_stringutils_string_contains(host, domain) == true)
	{
		/* use the default domain name if domain not present */
		qsc_stringutils_clear_string(domain);
		qsc_stringutils_copy_string(domain, QSC_NETUTILS_DOMAIN_NAME_SIZE, QSTP_CERTIFICATE_DEFAULT_DOMAIN);
	}

	qsc_memutils_clear(issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, domain);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, "_");
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, host);
	qsc_stringutils_concat_strings(issuer, QSTP_CERTIFICATE_ISSUER_SIZE, QSTP_SERVER_CERTIFICATE_EXTENSION_NAME);
}

void qstp_server_key_deserialize(qstp_server_signature_key* kset, const uint8_t input[QSTP_SERVER_SIGNATURE_KEY_SIZE])
{
	QSTP_ASSERT(kset != NULL);

	size_t pos;

	if (kset != NULL)
	{
		qsc_memutils_copy(kset->issuer, input, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos = QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(kset->schash, input + pos, QSTP_CERTIFICATE_HASH_SIZE);
		pos += QSTP_CERTIFICATE_HASH_SIZE;
		qsc_memutils_copy(kset->serial, input + pos, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(kset->sigkey, input + pos, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(kset->verkey, input + pos, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_memutils_copy(&kset->expiration, input + pos, QSTP_CERTIFICATE_EXPIRATION_SIZE);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		kset->algorithm = input[pos];
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		kset->version = input[pos];
	}
}

bool qstp_server_key_to_file(const qstp_server_signature_key* kset, const char* fpath)
{
	QSTP_ASSERT(fpath != NULL);
	QSTP_ASSERT(kset != NULL);

	uint8_t skset[QSTP_SERVER_SIGNATURE_KEY_SIZE] = { 0U };
	bool res;

	res = false;

	if (fpath != NULL && kset != NULL)
	{
		if (qsc_fileutils_exists(fpath) == true)
		{
			qsc_fileutils_delete(fpath);
		}

		qstp_server_key_serialize(skset, kset);
		res = qsc_fileutils_copy_stream_to_file(fpath, (const char*)skset, QSTP_SERVER_SIGNATURE_KEY_SIZE);
	}

	return res;
}

void qstp_server_key_serialize(uint8_t output[QSTP_SERVER_SIGNATURE_KEY_SIZE], const qstp_server_signature_key* kset)
{
	QSTP_ASSERT(kset != NULL);

	size_t pos;

	if (kset != NULL)
	{
		qsc_memutils_copy(output, kset->issuer, QSTP_CERTIFICATE_ISSUER_SIZE);
		pos = QSTP_CERTIFICATE_ISSUER_SIZE;
		qsc_memutils_copy(output + pos, kset->schash, QSTP_CERTIFICATE_HASH_SIZE);
		pos += QSTP_CERTIFICATE_HASH_SIZE;
		qsc_memutils_copy(output + pos, kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		pos += QSTP_CERTIFICATE_SERIAL_SIZE;
		qsc_memutils_copy(output + pos, kset->sigkey, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_SIGNING_KEY_SIZE;
		qsc_memutils_copy(output + pos, kset->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		pos += QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE;
		qsc_intutils_le64to8(output + pos, kset->expiration.from);
		qsc_intutils_le64to8(output + pos + sizeof(uint64_t), kset->expiration.to);
		pos += QSTP_CERTIFICATE_EXPIRATION_SIZE;
		output[pos] = kset->algorithm;
		pos += QSTP_CERTIFICATE_ALGORITHM_SIZE;
		output[pos] = kset->version;
	}
}

uint8_t qstp_version_from_string(const char* sver, size_t sverlen)
{
	QSTP_ASSERT(sver != NULL);

	uint8_t res;

	res = 0U;

	if (sver != NULL)
	{
		if (sver != NULL && sverlen > 0U)
		{
			if (qsc_stringutils_is_hex(sver, sverlen) == true)
			{
				res = qsc_stringutils_hex_to_byte(sver);
			}
		}
	}

	return res;
}

void qstp_version_to_string(char* sver, uint8_t version)
{
	QSTP_ASSERT(sver != NULL);

	if (sver != NULL)
	{
		qsc_stringutils_byte_to_hex(sver, version);
	}
}

#if defined(QSTP_DEBUG_MODE)
bool qstp_test_root_certificate_encoding(const qstp_root_certificate* root)
{
	QSTP_ASSERT(root != NULL);

	qstp_root_certificate rcpy = { 0 };
	char* enck;
	size_t elen;
	size_t slen;
	bool res;

	res = false;

	if (root != NULL)
	{
		elen = qstp_root_certificate_encoded_size();
		enck = qsc_memutils_malloc(elen);

		if (enck != NULL)
		{
			slen = qstp_root_certificate_encode(enck, elen, root);

			if (slen <= elen)
			{
				if (qstp_root_certificate_decode(&rcpy, enck, elen) == true)
				{
					res = qstp_root_certificate_compare(root, &rcpy);
				}
			}

			qsc_memutils_alloc_free(enck);
		}
	}

	return res;
}

bool qstp_test_server_certificate_encoding(const qstp_server_certificate* cert)
{
	QSTP_ASSERT(cert != NULL);

	qstp_server_certificate ccpy = { 0 };
	char* enck;
	size_t elen;
	size_t slen;
	bool res;

	res = false;

	if (cert != NULL)
	{
		elen = qstp_server_certificate_encoded_size();
		enck = qsc_memutils_malloc(elen);

		if (enck != NULL)
		{
			slen = qstp_server_certificate_encode(enck, elen, cert);

			if (slen <= elen)
			{
				if (qstp_server_certificate_decode(&ccpy, enck, elen) == true)
				{
					res = qstp_server_certificate_compare(cert, &ccpy);
				}
			}

			qsc_memutils_alloc_free(enck);
		}
	}

	return res;
}
#endif
