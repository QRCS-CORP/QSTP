#include "client.h"
#include "qstp.h"
#include "kex.h"
#include "logger.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "timestamp.h"

/** \cond */
typedef struct client_receiver_state
{
	qstp_connection_state* pcns;
	qstp_keep_alive_state* pkpa;
	void (*receive_callback)(qstp_connection_state*, const char*, size_t);
	void (*disconnect_callback)(qstp_connection_state*);
} client_receiver_state;
/** \endcond */

/* Private Functions */

/** \cond */
static void client_state_initialize(qstp_kex_client_state* kcs, qstp_connection_state* cns, const qstp_root_certificate* root, const qstp_server_certificate* cert)
{
	qstp_server_root_certificate_hash(kcs->schash, root, cert);

	qsc_memutils_copy(kcs->serial, cert->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
	qsc_memutils_copy(kcs->verkey, cert->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
	kcs->expiration = cert->expiration.to;
	cns->target.instance = qsc_acp_uint32();
	qstp_cipher_dispose(&cns->rxcpr);
	qstp_cipher_dispose(&cns->txcpr);
	cns->exflag = qstp_flag_none;
	cns->cid = 0;
	cns->rxseq = 0;
	cns->txseq = 0;
}

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		qstp_connection_close(prcv->pcns, qstp_error_none, true);
	}

	/* dispose of resources */
	qstp_connection_state_dispose(prcv->pcns);
}

static qstp_errors client_send_keep_alive(qstp_keep_alive_state* kctx, const qsc_socket* sock)
{
	assert(kctx != NULL);
	assert(sock != NULL);

	qstp_errors qerr;

	qerr = qstp_error_bad_keep_alive;

	if (qsc_socket_is_connected(sock) == true)
	{
		uint8_t spct[QSTP_PACKET_HEADER_SIZE + QSTP_CERTIFICATE_TIMESTAMP_SIZE] = { 0 };
		qstp_network_packet resp = { 0 };
		uint64_t etime;
		size_t slen;

		/* set the time and store in keep-alive struct */
		etime = qsc_timestamp_datetime_utc();
		kctx->etime = etime;

		/* assemble the keep-alive packet */
		resp.pmessage = spct + QSTP_PACKET_HEADER_SIZE;
		resp.flag = qstp_flag_keep_alive_request;
		resp.sequence = kctx->seqctr;
		resp.msglen = QSTP_CERTIFICATE_TIMESTAMP_SIZE;
		qsc_intutils_le64to8(resp.pmessage, etime);
		qstp_packet_header_serialize(&resp, spct);

		slen = qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);

		if (slen == QSTP_PACKET_HEADER_SIZE + QSTP_CERTIFICATE_TIMESTAMP_SIZE)
		{
			qerr = qstp_error_none;
		}
	}

	return qerr;
}

static void client_keepalive_loop(qstp_keep_alive_state* kpa)
{
	assert(kpa != NULL);

	qsc_mutex mtx;
	qstp_errors qerr;

	do
	{
		mtx = qsc_async_mutex_lock_ex();
		kpa->recd = false;
		qerr = client_send_keep_alive(kpa, &kpa->target);

		if (kpa->recd == false)
		{
			qerr = qstp_error_keepalive_expired;
		}

		qsc_async_mutex_unlock_ex(mtx);
		qsc_async_thread_sleep(QSTP_KEEPALIVE_TIMEOUT);
	} 
	while (qerr == qstp_error_none);
}

static void client_receive_loop(client_receiver_state* prcv)
{
	assert(prcv != NULL);

	qstp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qstp_errors qerr;

	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSTP_PACKET_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0;
			slen = 0;
			qsc_memutils_clear(rbuf, QSTP_PACKET_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, QSTP_PACKET_HEADER_SIZE);

			if (plen == QSTP_PACKET_HEADER_SIZE)
			{
				qstp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0 && pkt.msglen <= QSTP_PACKET_MESSAGE_MAX)
				{
					plen = pkt.msglen + QSTP_PACKET_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0)
						{
							pkt.pmessage = rbuf + QSTP_PACKET_HEADER_SIZE;

							if (pkt.flag == qstp_flag_encrypted_message)
							{
								uint8_t* mstr;

								slen = (pkt.msglen) - QSTP_MACTAG_SIZE;
								mstr = (uint8_t*)qsc_memutils_malloc(slen);

								if (mstr != NULL)
								{
									qsc_memutils_clear(mstr, slen);
									qerr = qstp_decrypt_packet(prcv->pcns, mstr, &mlen, &pkt);

									if (qerr == qstp_error_none)
									{
										prcv->receive_callback(prcv->pcns, mstr, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										qstp_log_write(qstp_messages_decryption_fail, cadd);
										break;
									}

									qsc_memutils_alloc_free(mstr);
								}
								else
								{
									/* close the connection on memory allocation failure */
									qstp_log_write(qstp_messages_allocate_fail, cadd);
									break;
								}
							}
							else if (pkt.flag == qstp_flag_connection_terminate)
							{
								qstp_log_write(qstp_messages_disconnect, cadd);
								break;
							}
							else if (pkt.flag == qstp_flag_keep_alive_request)
							{
								const size_t klen = QSTP_PACKET_HEADER_SIZE + QSTP_CERTIFICATE_TIMESTAMP_SIZE;
								/* copy the keep-alive packet and send it back */
								pkt.flag = qstp_flag_keep_alive_response;
								qstp_packet_header_serialize(&pkt, rbuf);
								qsc_socket_send(&prcv->pcns->target, rbuf, klen, qsc_socket_send_flag_none);
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
							qstp_log_write(qstp_messages_receive_fail, cadd);
							break;
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
				qstp_log_write(qstp_messages_receive_fail, cadd);
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qstp_log_write(qstp_messages_allocate_fail, cadd);
	}
}
/** \endcond */

/* Public Functions */

qstp_errors qstp_client_connect_ipv4(const qstp_root_certificate* root, 
	const qstp_server_certificate* cert,
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qstp_connection_state*), 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t))
{
	assert(root != NULL);
	assert(cert != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qstp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qstp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qstp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		if (qstp_root_certificate_verify(root, cert) == true)
		{
			kcs = (qstp_kex_client_state*)qsc_memutils_malloc(sizeof(qstp_kex_client_state));

			if (kcs != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qstp_kex_client_state));
				prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

				if (prcv != NULL)
				{
					qsc_memutils_clear(prcv, sizeof(client_receiver_state));
					prcv->pcns = (qstp_connection_state*)qsc_memutils_malloc(sizeof(qstp_connection_state));

					if (prcv->pcns != NULL)
					{
						prcv->receive_callback = receive_callback;

						/* connect to the server */
						qsc_socket_client_initialize(&prcv->pcns->target);
						serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

						if (serr == qsc_socket_exception_success)
						{
							/* initialize the client */
							client_state_initialize(kcs, prcv->pcns, root, cert);

							/* perform the key exchange */
							qerr = qstp_kex_client_key_exchange(kcs, prcv->pcns);
							qsc_memutils_alloc_free(kcs);
							kcs = NULL;

							if (qerr == qstp_error_none)
							{
								/* start the receive loop on a new thread */
								qsc_async_thread_create((void*)&client_receive_loop, prcv);

								/* start the send loop on the main thread */
								send_func(prcv->pcns);

								/* disconnect the socket */
								client_connection_dispose(prcv);
							}
							else
							{
								qstp_log_write(qstp_messages_kex_fail, (const char*)prcv->pcns->target.address);
								qerr = qstp_error_exchange_failure;
							}

							if (prcv != NULL && prcv->pcns != NULL)
							{
								qstp_connection_close(prcv->pcns, qstp_error_none, true);
							}
						}
						else
						{
							qstp_log_write(qstp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qstp_error_connection_failure;
						}
					}
					else
					{
						qstp_log_message(qstp_messages_allocate_fail);
						qerr = qstp_error_memory_allocation;
					}
				}
				else
				{
					qstp_log_message(qstp_messages_allocate_fail);
					qerr = qstp_error_memory_allocation;
				}
			}
			else
			{
				qstp_log_message(qstp_messages_allocate_fail);
				qerr = qstp_error_memory_allocation;
			}
		}
		else
		{
			qstp_log_message(qstp_messages_kex_fail);
			qerr = qstp_error_verify_failure;
		}
	}
	else
	{
		qstp_log_message(qstp_messages_invalid_request);
		qerr = qstp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->disconnect_callback = NULL;
		prcv->receive_callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}

qstp_errors qstp_client_connect_ipv6(const qstp_root_certificate* root, 
	const qstp_server_certificate* cert,
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qstp_connection_state*), 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t))
{
	assert(root != NULL);
	assert(cert != NULL);
	assert(send_func != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	qstp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qstp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qstp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		if (qstp_root_certificate_verify(root, cert) == true)
		{
			kcs = (qstp_kex_client_state*)qsc_memutils_malloc(sizeof(qstp_kex_client_state));

			if (kcs != NULL)
			{
				qsc_memutils_clear(kcs, sizeof(qstp_kex_client_state));
				prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));

				if (prcv != NULL)
				{
					qsc_memutils_clear(prcv, sizeof(client_receiver_state));
					prcv->pcns = (qstp_connection_state*)qsc_memutils_malloc(sizeof(qstp_connection_state));

					if (prcv->pcns != NULL)
					{
						prcv->receive_callback = receive_callback;
						qsc_socket_client_initialize(&prcv->pcns->target);

						serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

						if (serr == qsc_socket_exception_success)
						{
							/* initialize the client */
							client_state_initialize(kcs, prcv->pcns, root, cert);
							qerr = qstp_kex_client_key_exchange(kcs, prcv->pcns);
							qsc_memutils_alloc_free(kcs);
							kcs = NULL;

							if (qerr == qstp_error_none)
							{
								/* start the receive loop on a new thread */
								qsc_async_thread_create((void*)&client_receive_loop, prcv);

								/* start the send loop on the main thread */
								send_func(prcv->pcns);

								/* disconnect the socket */
								client_connection_dispose(prcv);
							}
							else
							{
								qstp_log_write(qstp_messages_kex_fail, (const char*)prcv->pcns->target.address);
								qerr = qstp_error_exchange_failure;
							}

							if (prcv && prcv->pcns)
							{
								qstp_connection_close(prcv->pcns, qstp_error_none, true);
							}
						}
						else
						{
							qstp_log_write(qstp_messages_kex_fail, (const char*)prcv->pcns->target.address);
							qerr = qstp_error_connection_failure;
						}
					}
					else
					{
						qstp_log_message(qstp_messages_allocate_fail);
						qerr = qstp_error_memory_allocation;
					}
				}
				else
				{
					qstp_log_message(qstp_messages_allocate_fail);
					qerr = qstp_error_memory_allocation;
				}
			}
			else
			{
				qstp_log_message(qstp_messages_allocate_fail);
				qerr = qstp_error_memory_allocation;
			}
		}
		else
		{
			qstp_log_message(qstp_messages_kex_fail);
			qerr = qstp_error_verify_failure;
		}
	}
	else
	{
		qstp_log_message(qstp_messages_invalid_request);
		qerr = qstp_error_invalid_input;
	}

	if (kcs != NULL)
	{
		qsc_memutils_alloc_free(kcs);
		kcs = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->receive_callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return qerr;
}
