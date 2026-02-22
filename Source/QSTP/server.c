#include "server.h"
#include "connections.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

/** \cond */
typedef struct server_receiver_state
{
	qstp_connection_state* pcns;
	const qstp_server_signature_key* kset;
	void (*receive_callback)(qstp_connection_state*, const char*, size_t);
	void (*disconnect_callback)(qstp_connection_state*);
} server_receiver_state;
/** \endcond */

/** \cond */
static bool m_server_pause;
static bool m_server_run;

static void server_state_initialize(qstp_kex_server_state* kss, const server_receiver_state* prcv)
{
	qsc_memutils_copy(kss->schash, prcv->kset->schash, QSTP_CERTIFICATE_HASH_SIZE);
	qsc_memutils_copy(kss->serial, prcv->kset->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(kss->sigkey, prcv->kset->sigkey, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
	qsc_memutils_copy(kss->verkey, prcv->kset->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	kss->prikey = NULL;
	kss->pubkey = NULL;
	kss->expiration = prcv->kset->expiration.to;
}

static void server_poll_sockets(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = qstp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		const qstp_connection_state* cns = qstp_connections_index(i);

		if (cns != NULL && qstp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == false)
			{
				qstp_connections_reset(cns->cid);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

static void server_receive_loop(void* prcv)
{
	QSTP_ASSERT(prcv != NULL);

	qstp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	qstp_kex_server_state* pkss;
	server_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qstp_errors qerr;

	pprcv = (server_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));
	pkss = (qstp_kex_server_state*)qsc_memutils_malloc(sizeof(qstp_kex_server_state));

	if (pkss != NULL)
	{
		server_state_initialize(pkss, prcv);
		qerr = qstp_kex_server_key_exchange(pkss, pprcv->pcns);
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (qerr == qstp_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_malloc(QSTP_PACKET_HEADER_SIZE);

			if (rbuf != NULL)
			{
				while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
				{
					mlen = 0U;
					slen = 0U;

					plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, QSTP_PACKET_HEADER_SIZE);

					if (plen == QSTP_PACKET_HEADER_SIZE)
					{
						qstp_packet_header_deserialize(rbuf, &pkt);

						if (pkt.msglen > 0U && pkt.msglen <= QSTP_PACKET_MESSAGE_MAX)
						{
							plen = pkt.msglen + QSTP_PACKET_HEADER_SIZE;
							rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

							if (rbuf != NULL)
							{
								qsc_memutils_clear(rbuf, plen);
								mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

								if (mlen != 0U)
								{
									pkt.pmessage = rbuf + QSTP_PACKET_HEADER_SIZE;

									if (pkt.flag == qstp_flag_encrypted_message)
									{
										uint8_t* mstr;

										slen = pkt.msglen + QSTP_MACTAG_SIZE;
										mstr = (uint8_t*)qsc_memutils_malloc(slen);

										if (mstr != NULL)
										{
											qsc_memutils_clear(mstr, slen);

											qerr = qstp_decrypt_packet(pprcv->pcns, mstr, &mlen, &pkt);

											if (qerr == qstp_error_none)
											{
												pprcv->receive_callback(pprcv->pcns, (char*)mstr, mlen);
												qsc_memutils_alloc_free(mstr);
											}
											else
											{
												/* close the connection on authentication failure */
												qstp_log_write(qstp_messages_decryption_fail, cadd);
												qsc_memutils_alloc_free(mstr);
												break;
											}
										}
										else
										{
											/* close the connection on memory allocation failure */
											qstp_log_write(qstp_messages_allocate_fail, cadd);
											break;
										}
									}
									else if (pkt.flag == qstp_flag_error_condition)
									{
										/* anti-dos: break on error message is conditional
										   on succesful authentication/decryption */
										if (qstp_decrypt_error_message(&qerr, pprcv->pcns, rbuf) == true)
										{
											qstp_log_system_error(qerr);
											break;
										}
									}
									else if (pkt.flag == qstp_flag_connection_terminate)
									{
										qstp_log_write(qstp_messages_disconnect, cadd);
										break;
									}
									else
									{
										/* unknown message type, we fail out of caution */
										qstp_log_write(qstp_messages_receive_fail, cadd);
										break;
									}
								}
								else
								{
									qsc_socket_exceptions err = qsc_socket_get_last_error();

									if (err != qsc_socket_exception_success)
									{
										qstp_log_error(qstp_messages_receive_fail, err, cadd);

										/* fatal socket errors */
										if (err == qsc_socket_exception_circuit_reset ||
											err == qsc_socket_exception_circuit_terminated ||
											err == qsc_socket_exception_circuit_timeout ||
											err == qsc_socket_exception_dropped_connection ||
											err == qsc_socket_exception_network_failure ||
											err == qsc_socket_exception_shut_down)
										{
											qstp_log_write(qstp_messages_connection_fail, cadd);
											break;
										}
									}
								}
							}
							else
							{
								/* close the connection on memory allocation failure */
								qstp_log_write(qstp_messages_allocate_fail, cadd);
								break;
							}
						}
						else
						{
							/* message size exceeds maximum allowable */
							qstp_log_write(qstp_messages_invalid_request, cadd);
						}
					}
				}

				qsc_memutils_alloc_free(rbuf);
			}
			else
			{
				/* close the connection on memory allocation failure */
				qstp_log_write(qstp_messages_allocate_fail, cadd);
			}

			if (pprcv->disconnect_callback != NULL)
			{
				pprcv->disconnect_callback(pprcv->pcns);
			}
		}
		else
		{
			qstp_log_message(qstp_messages_kex_fail);
		}

		if (pprcv != NULL)
		{
			qstp_connections_reset(pprcv->pcns->cid);
			qsc_memutils_alloc_free(pprcv);
			pprcv = NULL;
		}
	}
	else
	{
		qstp_log_message(qstp_messages_allocate_fail);
	}
}

static qstp_errors server_start(const qstp_server_signature_key* kset, 
	const qsc_socket* source, 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t),
	void (*disconnect_callback)(qstp_connection_state*))
{
	QSTP_ASSERT(kset != NULL);
	QSTP_ASSERT(source != NULL);
	QSTP_ASSERT(receive_callback != NULL);

	qsc_socket_exceptions res;
	qstp_errors qerr;

	qerr = qstp_error_none;
	m_server_pause = false;
	m_server_run = true;
	qstp_logger_initialize(NULL);
	qstp_connections_initialize(QSTP_CONNECTIONS_INIT, QSTP_CONNECTIONS_MAX);

	do
	{
		qstp_connection_state* cns = qstp_connections_next();

		if (cns != NULL)
		{
			res = qsc_socket_accept(source, &cns->target);

			if (res == qsc_socket_exception_success)
			{
				server_receiver_state* prcv = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (prcv != NULL)
				{
					cns->target.connection_status = qsc_socket_state_connected;
					prcv->pcns = cns;
					prcv->kset = kset;
					prcv->disconnect_callback = disconnect_callback;
					prcv->receive_callback = receive_callback;

					qstp_log_write(qstp_messages_connect_success, (const char*)cns->target.address);
					qsc_async_thread_create(&server_receive_loop, prcv);
					server_poll_sockets();
				}
				else
				{
					qstp_connections_reset(cns->cid);
					qerr = qstp_error_memory_allocation;
					qstp_log_message(qstp_messages_sockalloc_fail);
				}
			}
			else
			{
				qstp_connections_reset(cns->cid);
				qerr = qstp_error_accept_fail;
				qstp_log_message(qstp_messages_accept_fail);
			}
		}
		else
		{
			qerr = qstp_error_hosts_exceeded;
			qstp_log_message(qstp_messages_queue_empty);
		}

		while (m_server_pause == true)
		{
			qsc_async_thread_sleep(QSTP_SERVER_PAUSE_INTERVAL);
		}
	} 
	while (m_server_run == true);

	return qerr;
}
/** \endcond */

bool qstp_server_expiration_check(const qstp_server_signature_key* kset)
{
	uint64_t ctime;

	ctime = qsc_timestamp_datetime_utc();

	return (ctime < kset->expiration.to);
}

/* Public Functions */

void qstp_server_certificate_print(const qstp_server_certificate* cert)
{
	QSTP_ASSERT(cert != NULL);

	char* penk;
	size_t elen;
	size_t slen;

	elen = qstp_server_certificate_encoded_size();
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

void qstp_server_key_generate(qstp_server_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp)
{
	QSTP_ASSERT(kset != NULL);
	QSTP_ASSERT(exp != 0U);

	if (kset != NULL && exp != 0U)
	{
		uint64_t period;

		period = exp * 24 * 60 * 60;

		if (period >= QSTP_CERTIFICATE_MINIMUM_PERIOD && period <= QSTP_CERTIFICATE_MAXIMUM_PERIOD)
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

void qstp_server_pause(void)
{
	m_server_pause = true;
}

void qstp_server_quit(void)
{
	size_t clen;
	qsc_mutex mtx;

	clen = qstp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		qstp_connection_state* cns = qstp_connections_index(i);

		if (cns != NULL && qstp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsc_socket_close_socket(&cns->target);
			}

			qstp_connections_reset(cns->cid);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	qstp_connections_dispose();
	m_server_run = false;
}

void qstp_server_resume(void)
{
	m_server_pause = false;
}

qstp_errors qstp_server_start_ipv4(qsc_socket* source, 
	const qstp_server_signature_key* kset,
	void (*receive_callback)(qstp_connection_state*, const char*, size_t),
	void (*disconnect_callback)(qstp_connection_state*))
{
	QSTP_ASSERT(kset != NULL);
	QSTP_ASSERT(qsc_memutils_zeroed(kset->schash, QSTP_CERTIFICATE_HASH_SIZE) == false);
	QSTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv4_address addt = { 0 };
	qsc_socket_exceptions res;
	qstp_errors qerr;

	/* ensure that the caller has created the transcript hash */
	if (kset != NULL && qsc_memutils_zeroed(kset->schash, QSTP_CERTIFICATE_HASH_SIZE) == false && receive_callback != NULL)
	{
		addt = qsc_ipinfo_ipv4_address_any();
		qsc_socket_server_initialize(source);
		res = qsc_socket_create(source, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_bind_ipv4(source, &addt, QSTP_SERVER_PORT);

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					qerr = server_start(kset, source, receive_callback, disconnect_callback);
				}
				else
				{
					qerr = qstp_error_listener_fail;
					qstp_log_message(qstp_messages_listener_fail);
				}
			}
			else
			{
				qerr = qstp_error_connection_failure;
				qstp_log_message(qstp_messages_bind_fail);
			}
		}
		else
		{
			qerr = qstp_error_connection_failure;
			qstp_log_message(qstp_messages_create_fail);
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
		qstp_log_message(qstp_messages_invalid_request);
	}

	return qerr;
}

qstp_errors qstp_server_start_ipv6(qsc_socket* source,
	const qstp_server_signature_key* kset,
	void (*receive_callback)(qstp_connection_state*, const char*, size_t),
	void (*disconnect_callback)(qstp_connection_state*))
{
	QSTP_ASSERT(kset != NULL);
	QSTP_ASSERT(qsc_memutils_zeroed(kset->schash, QSTP_CERTIFICATE_HASH_SIZE) == false);
	QSTP_ASSERT(receive_callback != NULL);

	qsc_ipinfo_ipv6_address addt = { 0 };
	qsc_socket_exceptions res;
	qstp_errors qerr;

	/* ensure that the caller has created the transcript hash */
	if (kset != NULL && qsc_memutils_zeroed(kset->schash, QSTP_CERTIFICATE_HASH_SIZE) == false && receive_callback != NULL)
	{
		addt = qsc_ipinfo_ipv6_address_any();
		qsc_socket_server_initialize(source);
		res = qsc_socket_create(source, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_bind_ipv6(source, &addt, QSTP_SERVER_PORT);

			if (res == qsc_socket_exception_success)
			{
				res = qsc_socket_listen(source, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

				if (res == qsc_socket_exception_success)
				{
					qerr = server_start(kset, source, receive_callback, disconnect_callback);
				}
				else
				{
					qerr = qstp_error_listener_fail;
					qstp_log_message(qstp_messages_listener_fail);
				}
			}
			else
			{
				qerr = qstp_error_connection_failure;
				qstp_log_message(qstp_messages_bind_fail);
			}
		}
		else
		{
			qerr = qstp_error_connection_failure;
			qstp_log_message(qstp_messages_create_fail);
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
		qstp_log_message(qstp_messages_invalid_request);
	}

	return qerr;
}
