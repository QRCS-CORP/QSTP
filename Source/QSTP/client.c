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
	void (*receive_callback)(qstp_connection_state*, const char*, size_t);
	void (*disconnect_callback)(qstp_connection_state*);
} client_receiver_state;
/** \endcond */

/* Private Functions */

static void symmetric_ratchet(qstp_connection_state* cns, const uint8_t* secret, size_t seclen)
{
	qsc_keccak_state kstate = { 0 };
	qstp_cipher_keyparams kp = { 0 };
	uint8_t prnd[QSC_KECCAK_256_RATE] = { 0U };

	/* re-key the ciphers using the token, ratchet key, and configuration name */
	qsc_cshake_initialize(&kstate, qsc_keccak_rate_512, secret, seclen, (const uint8_t*)QSTP_PROTOCOL_SET_STRING, QSTP_PROTOCOL_SET_SIZE, cns->rtcs, QSTP_SYMMETRIC_KEY_SIZE);
	/* re-key the ciphers using the symmetric ratchet key */
	qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_512, prnd, 3);

	if (cns->receiver == true)
	{
		/* initialize for decryption, and raise client channel rx */
		kp.key = prnd;
		kp.keylen = QSTP_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSTP_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qstp_cipher_initialize(&cns->rxcpr, &kp, false);

		/* initialize for encryption, and raise client channel tx */
		kp.key = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE;
		kp.keylen = QSTP_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE + QSTP_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qstp_cipher_initialize(&cns->txcpr, &kp, true);
	}
	else
	{
		/* initialize for encryption, and raise tx */
		kp.key = prnd;
		kp.keylen = QSTP_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSTP_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qstp_cipher_initialize(&cns->txcpr, &kp, true);

		/* initialize decryption, and raise rx */
		kp.key = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE;
		kp.keylen = QSTP_SYMMETRIC_KEY_SIZE;
		kp.nonce = ((uint8_t*)prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE + QSTP_SYMMETRIC_KEY_SIZE);
		kp.info = NULL;
		kp.infolen = 0U;
		qstp_cipher_initialize(&cns->rxcpr, &kp, false);
	}

	/* permute key state and store next key */
	qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);
	qsc_memutils_copy(cns->rtcs, (uint8_t*)kstate.state, QSTP_SYMMETRIC_KEY_SIZE);
	/* erase the key array */
	qsc_memutils_secure_erase(prnd, sizeof(prnd));
	qsc_memutils_secure_erase((uint8_t*)&kp, sizeof(qstp_cipher_keyparams));
}

static bool symmetric_ratchet_response(qstp_connection_state* cns, const qstp_network_packet* packetin)
{
	uint8_t rkey[QSTP_RTOK_SIZE] = { 0U };
	uint8_t shdr[QSTP_PACKET_HEADER_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;
	cns->rxseq += 1U;

	if (packetin->sequence == cns->rxseq)
	{
		/* serialize the header and add it to the ciphers associated data */
		qstp_packet_header_serialize(packetin, shdr);
		qstp_cipher_set_associated(&cns->rxcpr, shdr, QSTP_PACKET_HEADER_SIZE);
		mlen = packetin->msglen - (size_t)QSTP_MACTAG_SIZE;

		/* authenticate then decrypt the data */
		if (qstp_cipher_transform(&cns->rxcpr, rkey, packetin->pmessage, mlen) == true)
		{
			/* inject into key state */
			symmetric_ratchet(cns, rkey, sizeof(rkey));
			res = true;
		}
	}

	qsc_memutils_secure_erase(rkey, sizeof(rkey));
	qsc_memutils_clear(shdr, sizeof(shdr));

	return res;
}

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
	cns->cid = 0U;
	cns->rxseq = 0U;
	cns->txseq = 0U;
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

static void client_receive_loop(void* prcv)
{
	QSTP_ASSERT(prcv != NULL);

	qstp_network_packet pkt = { 0 };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0 };
	client_receiver_state* pprcv;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	qstp_errors qerr;

	pprcv = (client_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(QSTP_PACKET_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, QSTP_PACKET_HEADER_SIZE);

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

						if (mlen > 0U)
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
									qerr = qstp_decrypt_packet(pprcv->pcns, mstr, &mlen, &pkt);

									if (qerr == qstp_error_none)
									{
										pprcv->receive_callback(pprcv->pcns, (const char*)mstr, mlen);
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
							else if (pkt.flag == qstp_flag_symmetric_ratchet_request)
							{
								if (symmetric_ratchet_response(pprcv->pcns, &pkt) == false)
								{
									qstp_log_write(qstp_messages_symmetric_ratchet, (const char*)pprcv->pcns->target.address);
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

bool qstp_send_symmetric_ratchet_request(qstp_connection_state* cns)
{
	QSTP_ASSERT(cns != NULL);

	size_t plen;
	size_t slen;
	bool res;

	res = false;

	if (cns != NULL)
	{
		qstp_network_packet pkt = { 0 };
		uint8_t pmsg[QSTP_RTOK_SIZE + QSTP_MACTAG_SIZE] = { 0U };
		uint8_t rkey[QSTP_RTOK_SIZE] = { 0U };

		/* generate the token key */
		if (qsc_acp_generate(rkey, sizeof(rkey)) == true)
		{
			uint8_t shdr[QSTP_PACKET_HEADER_SIZE] = { 0U };
			uint8_t spct[QSTP_PACKET_HEADER_SIZE + QSTP_RTOK_SIZE + QSTP_MACTAG_SIZE] = { 0U };

			cns->txseq += 1U;
			pkt.pmessage = pmsg;
			pkt.flag = qstp_flag_symmetric_ratchet_request;
			pkt.msglen = QSTP_RTOK_SIZE + QSTP_MACTAG_SIZE;
			pkt.sequence = cns->txseq;

			/* serialize the header and add it to the ciphers associated data */
			qstp_packet_header_serialize(&pkt, shdr);
			qstp_cipher_set_associated(&cns->txcpr, shdr, QSTP_PACKET_HEADER_SIZE);
			/* encrypt the message */
			qstp_cipher_transform(&cns->txcpr, pkt.pmessage, rkey, sizeof(rkey));

			/* convert the packet to bytes */
			plen = qstp_packet_to_stream(&pkt, spct);

			/* send the ratchet request */
			slen = qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

			if (slen == plen)
			{
				symmetric_ratchet(cns, rkey, sizeof(rkey));
				res = true;
			}

			qsc_memutils_clear(shdr, sizeof(shdr));
			qsc_memutils_clear(spct, sizeof(spct));
		}

		qsc_memutils_clear(pmsg, sizeof(pmsg));
		qsc_memutils_secure_erase(rkey, sizeof(rkey));
	}

	return res;
}

qstp_errors qstp_client_connect_ipv4(const qstp_root_certificate* root, 
	const qstp_server_certificate* cert,
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qstp_connection_state*), 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t))
{
	QSTP_ASSERT(root != NULL);
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(address != NULL);
	QSTP_ASSERT(send_func != NULL);
	QSTP_ASSERT(receive_callback != NULL);

	qstp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qstp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qstp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		if (qstp_server_root_certificate_verify(root, cert) == true)
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
								qsc_async_thread_create(&client_receive_loop, prcv);

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
	QSTP_ASSERT(root != NULL);
	QSTP_ASSERT(cert != NULL);
	QSTP_ASSERT(address != NULL);
	QSTP_ASSERT(send_func != NULL);
	QSTP_ASSERT(receive_callback != NULL);

	qstp_kex_client_state* kcs;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	qstp_errors qerr;

	kcs = NULL;
	prcv = NULL;
	qstp_logger_initialize(NULL);

	if (address != NULL && send_func != NULL && receive_callback != NULL)
	{
		if (qstp_server_root_certificate_verify(root, cert) == true)
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
								qsc_async_thread_create(&client_receive_loop, prcv);

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
