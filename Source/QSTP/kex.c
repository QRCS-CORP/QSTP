#include "kex.h"
#include "../../QSC/QSC/acp.h"
#include "../../QSC/QSC/encoding.h"
#include "../../QSC/QSC/intutils.h"
#include "../../QSC/QSC/memutils.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/sha3.h"
#include "../../QSC/QSC/socketserver.h"
#include "../../QSC/QSC/stringutils.h"
#include "../../QSC/QSC/timestamp.h"

#define KEX_CONNECT_REQUEST_MESSAGE_SIZE (QSTP_CERTIFICATE_SERIAL_SIZE + QSTP_PROTOCOL_SET_SIZE)
#define KEX_CONNECT_REQUEST_PACKET_SIZE (QSTP_PACKET_HEADER_SIZE + KEX_CONNECT_REQUEST_MESSAGE_SIZE)
#define KEX_CONNECT_RESPONSE_MESSAGE_SIZE (QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE + QSTP_CERTIFICATE_HASH_SIZE + QSTP_ASYMMETRIC_SIGNATURE_SIZE)
#define KEX_CONNECT_RESPONSE_PACKET_SIZE (QSTP_PACKET_HEADER_SIZE + KEX_CONNECT_RESPONSE_MESSAGE_SIZE)
#define KEX_EXCHANGE_REQUEST_MESSAGE_SIZE (QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE)
#define KEX_EXCHANGE_REQUEST_PACKET_SIZE (QSTP_PACKET_HEADER_SIZE + KEX_EXCHANGE_REQUEST_MESSAGE_SIZE)
#define KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE (0)
#define KEX_EXCHANGE_RESPONSE_PACKET_SIZE (QSTP_PACKET_HEADER_SIZE + KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE)

static void kex_subheader_serialize(uint8_t* pstream, const qstp_network_packet* packetin)
{
	qsc_intutils_le64to8(pstream, packetin->sequence);
	qsc_intutils_le64to8(pstream + sizeof(uint64_t), packetin->utctime);
}

static void kex_send_network_error(const qsc_socket* sock, qstp_errors error)
{
	assert(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		qstp_network_packet resp = { 0 };
		uint8_t spct[QSTP_PACKET_HEADER_SIZE + QSTP_PACKET_ERROR_SIZE] = { 0 };

		resp.pmessage = spct + QSTP_PACKET_HEADER_SIZE;
		qstp_packet_error_message(&resp, error);
		qstp_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

static void kex_client_reset(qstp_kex_client_state* kcs)
{
	assert(kcs != NULL);

	if (kcs != NULL)
	{
		qsc_memutils_clear(kcs->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(kcs->schash, QSTP_CERTIFICATE_HASH_SIZE);
		qsc_memutils_clear(kcs->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		kcs->expiration = 0;
	}
}

static bool kex_server_serial_verify(const uint8_t* keyid, const uint8_t* message)
{
	bool res;

	res = (qsc_intutils_verify(keyid, message, QSTP_CERTIFICATE_SERIAL_SIZE) == 0);

	return res;
}

static void kex_server_reset(qstp_kex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		qsc_memutils_clear(kss->schash, QSTP_CERTIFICATE_HASH_SIZE);
		qsc_memutils_clear(kss->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
		qsc_memutils_clear(kss->sigkey, QSTP_ASYMMETRIC_SIGNING_KEY_SIZE);
		qsc_memutils_clear(kss->verkey, QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE);
		kss->expiration = 0;
	}
}

static void kex_dispose_private_key(qstp_kex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		if (kss->prikey != NULL)
		{
			qsc_memutils_alloc_free(kss->prikey);
			kss->prikey = NULL;
		}
	}
}

static void kex_dispose_public_key(qstp_kex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		if (kss->pubkey != NULL)
		{
			qsc_memutils_alloc_free(kss->pubkey);
			kss->pubkey = NULL;
		}
	}
}

static void kex_initialize_cipher_keys(qstp_kex_server_state* kss)
{
	assert(kss != NULL);

	if (kss != NULL)
	{
		kss->prikey = qsc_memutils_malloc(QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE);

		if (kss->prikey != NULL)
		{
			qsc_memutils_clear(kss->prikey, QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE);
			kss->pubkey = qsc_memutils_malloc(QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);

			if (kss->pubkey != NULL)
			{
				qsc_memutils_clear(kss->pubkey, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
			}
		}
	}
}

/*
Legend:
<-, ->		-Assignment operators
:=, !=, ?=	-Equality operators; equals, not equals, evaluate
C			-The client host, initiates the exchange
S			-The server host, listens for a connection
AG			-The asymmetric cipher key generator function
-AEsk		-The asymmetric decapsulation function and secret key
AEpk		-The asymmetric encapsulation function and public key
ASsk		-Sign data with the secret signature key
AVpk		-Verify a signature the public verification key
cfg			-The protocol configuration string
cond,		-A conditional statement
cprrx		-A receive channels symmetric cipher instance
cprtx		-A transmit channels symmetric cipher instance
cpt			-The symmetric ciphers cipher-text
cpta		-The asymmetric ciphers cipher-text
-Ek			-The symmetric decryption function and key
Ek			-The symmetric encryption function and key
H			-The hash function (SHA3)
k,mk		-A symmetric cipher or MAC key
KDF			-The key expansion function (SHAKE)
kid			-The public keys unique identity array
Mmk			-The MAC function and key (KMAC)
pk,sk		-Asymmetric public and secret keys
pvk			-Public signature verification key
sch			-A hash of the configuration string and and asymmetric verification-keys
sec			-The shared secret derived from asymmetric encapsulation and decapsulation
spkh		-The signed hash of the asymmetric public encapsulation-key
*/

/*
The client sends a connection request with its configuration string, and asymmetric public signature key serial number.
The serial number is a multi-part 16-byte address and certificate identification array, 
used to match the intended target to the corresponding key. 
The configuration string defines the cryptographic protocol set being used, this must match both implementations configuration settings.
The client stores a hash of the configuration string, the serial number, and of the servers public asymmetric signature verification-key, 
which is used as a session cookie during the exchange.
sch <- H(cfg || serial || pvk)
The client sends the key identity string, and the configuration string to the server.
C{ serial, cfg } -> S
*/
static qstp_errors kex_client_connect_request(qstp_kex_client_state* kcs, qstp_connection_state* cns, qstp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetout != NULL);

	qsc_keccak_state kstate = { 0 };
	qstp_errors qerr;
	uint64_t tm;

	if (kcs != NULL && packetout != NULL)
	{
		tm = qsc_timestamp_datetime_utc();

		if (tm <= kcs->expiration)
		{
			/* copy the serial number and configuration string to the message */
			qsc_memutils_copy(packetout->pmessage, kcs->serial, QSTP_CERTIFICATE_SERIAL_SIZE);
			qsc_memutils_copy(packetout->pmessage + QSTP_CERTIFICATE_SERIAL_SIZE, QSTP_PROTOCOL_SET_STRING, QSTP_PROTOCOL_SET_SIZE);
			/* assemble the connection-request packet */
			qstp_header_create(packetout, qstp_flag_connect_request, cns->txseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			qerr = qstp_error_none;
			cns->exflag = qstp_flag_connect_request;
		}
		else
		{
			qerr = qstp_error_key_expired;
			cns->exflag = qstp_flag_none;
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
	}

	return qerr;
}

/*
Exchange Request:
The client verifies the signature of the hash, then generates its own hash of the asymmetric cipher public key, 
and compares it with the one contained in the message. 
If the hash matches, the client uses the public-key to encapsulate a shared secret.
cond <- AVpk(H(hdr | schash | pubk)) = (true ?= pk : 0)
cpt, sec <- AEpk(sec)
The client combines the secret and the session cookie to create the session keys, and two unique nonce, 
one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k2,n2)
cprtx(k1,n1)
*/
static qstp_errors kex_client_exchange_request(const qstp_kex_client_state* kcs, qstp_connection_state* cns, const qstp_network_packet* packetin, qstp_network_packet* packetout)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t khash[QSTP_CERTIFICATE_HASH_SIZE] = { 0 };
	size_t mlen;
	size_t slen;
	qstp_errors qerr;

	if (kcs != NULL && packetin != NULL && packetout != NULL)
	{
		if (cns->exflag == qstp_flag_connect_request && packetin->flag == qstp_flag_connect_response)
		{
			slen = 0;
			mlen = QSTP_ASYMMETRIC_SIGNATURE_SIZE + QSTP_CERTIFICATE_HASH_SIZE;

			/* verify the asymmetric signature */
			if (qstp_signature_verify(khash, &slen, packetin->pmessage, mlen, kcs->verkey) == true)
			{
				qsc_keccak_state kstate = { 0 };
				uint8_t phash[QSTP_CERTIFICATE_HASH_SIZE] = { 0 };
				uint8_t phdr[QSTP_PACKET_HEADER_SIZE] = { 0 };
				uint8_t ssec[QSTP_SECRET_SIZE] = { 0 };
				uint8_t* pubk;

				pubk = packetin->pmessage + mlen;

				/* hash the packet header, asymmetric public key, and serial/config hash */
				qsc_sha3_initialize(&kstate);
				qstp_packet_header_serialize(packetin, phdr);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, phdr, QSTP_PACKET_HEADER_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, kcs->schash, QSTP_CERTIFICATE_HASH_SIZE);
				qsc_sha3_update(&kstate, qsc_keccak_rate_256, pubk, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
				qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);
				qsc_keccak_dispose(&kstate);

				/* compare hashes */
				if (qsc_intutils_verify(phash, khash, QSTP_CERTIFICATE_HASH_SIZE) == 0)
				{
					uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };

					/* generate, and encapsulate the secret */

					/* store the cipher-text in the message */
					qstp_cipher_encapsulate(ssec, packetout->pmessage, pubk, qsc_acp_generate);

					/* assemble the exchange-request packet */
					qstp_header_create(packetout, qstp_flag_exchange_request, cns->txseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

					/* initialize cSHAKE k = H(sec, sch) */
					qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, QSTP_SECRET_SIZE, kcs->schash, QSTP_CERTIFICATE_HASH_SIZE, NULL, 0);
					qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);
					/* permute the state so we are not storing the current key */
					qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);

					/* initialize the symmetric cipher, and raise client channel-1 tx */
					qstp_cipher_keyparams kp1;
					kp1.key = prnd;
					kp1.keylen = QSTP_SYMMETRIC_KEY_SIZE;
					kp1.nonce = prnd + QSTP_SYMMETRIC_KEY_SIZE;
					kp1.info = NULL;
					kp1.infolen = 0;
					qstp_cipher_initialize(&cns->txcpr, &kp1, true);

					/* initialize the symmetric cipher, and raise client channel-1 rx */
					qstp_cipher_keyparams kp2;
					kp2.key = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE;
					kp2.keylen = QSTP_SYMMETRIC_KEY_SIZE;
					kp2.nonce = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE + QSTP_SYMMETRIC_KEY_SIZE;
					kp2.info = NULL;
					kp2.infolen = 0;
					qstp_cipher_initialize(&cns->rxcpr, &kp2, false);

					cns->exflag = qstp_flag_exchange_request;
					qerr = qstp_error_none;
				}
				else
				{
					cns->exflag = qstp_flag_none;
					qerr = qstp_error_verify_failure;
				}
			}
			else
			{
				cns->exflag = qstp_flag_none;
				qerr = qstp_error_authentication_failure;
			}
		}
		else
		{
			cns->exflag = qstp_flag_none;
			qerr = qstp_error_invalid_request;
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
	}

	return qerr;
}

/*
Establish Verify:
The client checks the flag of the exchange response packet sent by the server. 
If the flag is set to indicate an error state, the tunnel is torn down on both sides,
otherwise the client tunnel is established and in an operational state.
The client sets the operational state to session established, and is now ready to process data.
*/
static qstp_errors kex_client_establish_verify(const qstp_kex_client_state* kcs, qstp_connection_state* cns, const qstp_network_packet* packetin)
{
	assert(kcs != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);

	qstp_errors qerr;

	if (kcs != NULL && packetin != NULL)
	{
		if (cns->exflag == qstp_flag_exchange_request && packetin->flag == qstp_flag_exchange_response)
		{
			cns->exflag = qstp_flag_session_established;
			qerr = qstp_error_none;
		}
		else
		{
			cns->exflag = qstp_flag_none;
			qerr = qstp_error_invalid_request;
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
	}

	return qerr;
}

/*
Connect Response:
The server responds with either an error message, or a response packet. 
Any error during the key exchange will generate an error-packet sent to the remote host, 
which will trigger a tear down of the session and network connection on both sides.
The server first checks that it has the requested asymmetric signature verification key corresponding to that host 
using the serial number array, then verifies that it has a compatible protocol configuration. 
The server stores a hash of the configuration string, key id, and the public signature verification-key, to create the session cookie hash.
sch <- H(cfg || serial || pvk)
The server then generates an asymmetric encryption key-pair, stores the private key, hashes the public encapsulation key, 
and then signs the hash of the public encapsulation key using the asymmetric signature key. 
The public signature verification key can itself be signed by a ‘chain of trust' model, 
like X.509, using a signature verification extension to this protocol. 
pk, sk <- AG(cfg)
pkh <- H(pk)
spkh <- ASsk(pkh)
The server sends a connect response message containing a signed hash of the public asymmetric encapsulation-key, and a copy of that key.
S{ spkh, pk } -> C
*/
static qstp_errors kex_server_connect_response(qstp_kex_server_state* kss, qstp_connection_state* cns, const qstp_network_packet* packetin, qstp_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	uint8_t phash[QSTP_CERTIFICATE_HASH_SIZE] = { 0 };
	qsc_keccak_state kstate = { 0 };
	const uint8_t* pconf;
	qstp_errors qerr;
	uint64_t tm;
	size_t mlen;

	qerr = qstp_error_invalid_input;

	if (cns != NULL && kss != NULL && packetin != NULL && packetout != NULL)
	{
		/* compare the state serial number to the id in the message */
		if (kex_server_serial_verify(kss->serial, packetin->pmessage) == true)
		{
			tm = qsc_timestamp_datetime_utc();

			/* check the keys expiration date */
			if (tm <= kss->expiration)
			{
				/* get the configuration string */
				pconf = packetin->pmessage + QSTP_CERTIFICATE_SERIAL_SIZE, QSTP_PROTOCOL_SET_SIZE;
				
				/* compare the state configuration string to the message configuration string */
				if (qsc_memutils_are_equal(pconf, QSTP_PROTOCOL_SET_STRING, QSTP_PROTOCOL_SET_SIZE - 1) == true)
				{
					uint8_t phdr[QSTP_PACKET_HEADER_SIZE] = { 0 };

					/* initialize the packet and asymmetric encryption keys */
					kex_initialize_cipher_keys(kss);

					/* generate the asymmetric encryption key-pair */
					qstp_cipher_generate_keypair(kss->pubkey, kss->prikey, qsc_acp_generate);

					/* assemble the connection-response packet */
					qstp_header_create(packetout, qstp_flag_connect_response, cns->txseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

					/* hash the packet header, public encapsulation key, and the serial/config hash */
					qsc_sha3_initialize(&kstate);
					qstp_packet_header_serialize(packetout, phdr);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, phdr, QSTP_PACKET_HEADER_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->schash, QSTP_CERTIFICATE_HASH_SIZE);
					qsc_sha3_update(&kstate, qsc_keccak_rate_256, kss->pubkey, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					qsc_sha3_finalize(&kstate, qsc_keccak_rate_256, phash);
					qsc_keccak_dispose(&kstate);

					/* sign the hash and add it to the message */
					mlen = 0;
					qstp_signature_sign(packetout->pmessage, &mlen, phash, QSTP_CERTIFICATE_HASH_SIZE, kss->sigkey, qsc_acp_generate);

					/* copy the public key to the message */
					qsc_memutils_copy(packetout->pmessage + mlen, kss->pubkey, QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE);
					/* dispose of the public key array */
					kex_dispose_public_key(kss);

					qerr = qstp_error_none;
					cns->exflag = qstp_flag_connect_response;
				}
				else
				{
					qerr = qstp_error_unknown_protocol;
				}
			}
			else
			{
				qerr = qstp_error_key_expired;
			}
		}
		else
		{
			qerr = qstp_error_key_unrecognized;
		}
	}

	return qerr;
}

/*
Exchange Response:
The server decapsulates the shared-secret.
sec <- -AEsk(cpt)
The server combines the shared secret and the session cookie hash to create two session keys, 
and two unique nonce, one key-nonce pair for each channel of the communications stream.
k1, k2, n1, n2 <- KDF(sec, sch)
The receive and transmit channel ciphers are initialized.
cprrx(k1,n1)
cprtx(k2,n2)
The server sets the packet flag to exchange response, indicating that the encrypted channels have been raised, 
and sends the notification to the client. The server sets the operational state to session established, 
and is now ready to process data.
S{ f } -> C
*/
static qstp_errors kex_server_exchange_response(qstp_kex_server_state* kss, qstp_connection_state* cns, const qstp_network_packet* packetin, qstp_network_packet* packetout)
{
	assert(kss != NULL);
	assert(cns != NULL);
	assert(packetin != NULL);
	assert(packetout != NULL);

	qstp_errors qerr;

	if (kss != NULL && packetin != NULL && packetout != NULL)
	{
		if (cns->exflag == qstp_flag_connect_response && packetin->flag == qstp_flag_exchange_request)
		{
			uint8_t ssec[QSTP_SECRET_SIZE] = { 0 };

				/* decapsulate the shared secret */
			if (qstp_cipher_decapsulate(ssec, packetin->pmessage, kss->prikey) == true)
			{
				qsc_keccak_state kstate = { 0 };
				uint8_t prnd[QSC_KECCAK_256_RATE] = { 0 };

				/* dispose of the private asymmetric key */
				kex_dispose_private_key(kss);
				/* initialize cSHAKE k = H(ssec, sch) */
				qsc_cshake_initialize(&kstate, qsc_keccak_rate_256, ssec, sizeof(ssec), kss->schash, QSTP_CERTIFICATE_HASH_SIZE, NULL, 0);
				qsc_cshake_squeezeblocks(&kstate, qsc_keccak_rate_256, prnd, 1);
				/* permute the state so we are not storing the current key */
				qsc_keccak_permute(&kstate, QSC_KECCAK_PERMUTATION_ROUNDS);

				/* initialize the symmetric cipher, and raise client channel-1 tx */
				qstp_cipher_keyparams kp1;
				kp1.key = prnd;
				kp1.keylen = QSTP_SYMMETRIC_KEY_SIZE;
				kp1.nonce = prnd + QSTP_SYMMETRIC_KEY_SIZE;
				kp1.info = NULL;
				kp1.infolen = 0;
				qstp_cipher_initialize(&cns->rxcpr, &kp1, false);

				/* initialize the symmetric cipher, and raise client channel-1 rx */
				qstp_cipher_keyparams kp2;
				kp2.key = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE;
				kp2.keylen = QSTP_SYMMETRIC_KEY_SIZE;
				kp2.nonce = prnd + QSTP_SYMMETRIC_KEY_SIZE + QSTP_NONCE_SIZE + QSTP_SYMMETRIC_KEY_SIZE;
				kp2.info = NULL;
				kp2.infolen = 0;
				qstp_cipher_initialize(&cns->txcpr, &kp2, true);

				/* assemble the exchange-response packet */
				qstp_header_create(packetout, qstp_flag_exchange_response, cns->txseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

				qerr = qstp_error_none;
				cns->exflag = qstp_flag_session_established;
			}
			else
			{
				qerr = qstp_error_decapsulation_failure;
				cns->exflag = qstp_flag_none;
			}
		}
		else
		{
			qerr = qstp_error_invalid_request;
			cns->exflag = qstp_flag_none;
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
	}

	return qerr;
}

qstp_errors qstp_kex_client_key_exchange(qstp_kex_client_state* kcs, qstp_connection_state* cns)
{
	assert(kcs != NULL);
	assert(cns != NULL);

	qstp_network_packet reqt = { 0 };
	qstp_network_packet resp = { 0 };
	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qstp_errors qerr;
	
	if (kcs != NULL && cns != NULL)
	{
		sbuf = qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

		if (sbuf != NULL)
		{
			/* create the connection request packet */
			qsc_memutils_clear(sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);
			reqt.pmessage = sbuf + QSTP_PACKET_HEADER_SIZE;

			qerr = kex_client_connect_request(kcs, cns, &reqt);
			qstp_packet_header_serialize(&reqt, sbuf);

			if (qerr == qstp_error_none)
			{
				/* send the connection request */
				slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

				if (slen == KEX_CONNECT_REQUEST_PACKET_SIZE)
				{
					cns->txseq += 1;
					rbuf = qsc_memutils_malloc(KEX_CONNECT_RESPONSE_PACKET_SIZE);

					if (rbuf != NULL)
					{
						/* blocking receive waits for server */
						rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

						if (rlen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							qstp_packet_header_deserialize(rbuf, &resp);
							resp.pmessage = rbuf + QSTP_PACKET_HEADER_SIZE;

							qerr = qstp_header_validate(cns, &resp, qstp_flag_connect_response, cns->rxseq, KEX_CONNECT_RESPONSE_MESSAGE_SIZE);

							if (qerr == qstp_error_none)
							{
								sbuf = qsc_memutils_realloc(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

								if (sbuf != NULL)
								{
									/* clear the request packet */
									qsc_memutils_clear(sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);
									reqt.pmessage = sbuf + QSTP_PACKET_HEADER_SIZE;

									/* create the exstart request packet */
									qerr = kex_client_exchange_request(kcs, cns, &resp, &reqt);
									qstp_packet_header_serialize(&reqt, sbuf);
									
									if (qerr == qstp_error_none)
									{
										slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

										if (slen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
										{
											cns->txseq += 1;
											rbuf = qsc_memutils_realloc(rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

											if (rbuf != NULL)
											{
												rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

												if (rlen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
												{
													qstp_packet_header_deserialize(rbuf, &resp);
													qerr = qstp_header_validate(cns, &resp, qstp_flag_exchange_response, cns->rxseq, KEX_EXCHANGE_RESPONSE_MESSAGE_SIZE);

													if (qerr == qstp_error_none)
													{
														/* verify the exchange  */
														qerr = kex_client_establish_verify(kcs, cns, &resp);
													}
													else
													{
														qerr = qstp_error_packet_unsequenced;
													}
												}
												else
												{
													qerr = qstp_error_receive_failure;
												}
											}
											else
											{
												qerr = qstp_error_memory_allocation;
											}
										}
										else
										{
											qerr = qstp_error_transmit_failure;
										}
									}
								}
								else
								{
									qerr = qstp_error_memory_allocation;
								}
							}
							else
							{
								qerr = qstp_error_packet_unsequenced;
							}
						}
						else
						{
							qerr = qstp_error_receive_failure;
						}

						qsc_memutils_alloc_free(rbuf);
					}
					else
					{
						qerr = qstp_error_memory_allocation;
					}
				}
				else
				{
					qerr = qstp_error_transmit_failure;
				}
			}

			qsc_memutils_alloc_free(sbuf);
		}
		else
		{
			qerr = qstp_error_memory_allocation;
		}

		kex_client_reset(kcs);

		if (qerr != qstp_error_none)
		{
			if (cns->target.connection_status == qsc_socket_state_connected)
			{
				kex_send_network_error(&cns->target, qerr);
				qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
			}

			qstp_connection_state_dispose(cns);
		}
	}
	else
	{
		qerr = qstp_error_invalid_input;
	}
	
	return qerr;
}

qstp_errors qstp_kex_server_key_exchange(qstp_kex_server_state* kss, qstp_connection_state* cns)
{
	assert(kss != NULL);
	assert(cns != NULL);

	qstp_network_packet reqt = { 0 };
	qstp_network_packet resp = { 0 };
	uint8_t* rbuf;
	uint8_t* sbuf;
	size_t rlen;
	size_t slen;
	qstp_errors qerr;

	cns->exflag = qstp_flag_none;

	rbuf = qsc_memutils_malloc(KEX_CONNECT_REQUEST_PACKET_SIZE);

	if (rbuf != NULL)
	{
		qsc_memutils_clear(rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE);

		/* blocking receive waits for client */
		rlen = qsc_socket_receive(&cns->target, rbuf, KEX_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

		if (rlen == KEX_CONNECT_REQUEST_PACKET_SIZE)
		{
			/* convert client request to packet */
			qstp_packet_header_deserialize(rbuf, &reqt);
			reqt.pmessage = rbuf + QSTP_PACKET_HEADER_SIZE;

			qerr = qstp_header_validate(cns, &reqt, qstp_flag_connect_request, cns->rxseq, KEX_CONNECT_REQUEST_MESSAGE_SIZE);

			if (qerr == qstp_error_none)
			{
				sbuf = qsc_memutils_malloc(KEX_CONNECT_RESPONSE_PACKET_SIZE);

				if (sbuf != NULL)
				{
					qsc_memutils_clear(sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE);
					resp.pmessage = sbuf + QSTP_PACKET_HEADER_SIZE;

					/* create the connection request packet */
					qerr = kex_server_connect_response(kss, cns, &reqt, &resp);

					if (qerr == qstp_error_none)
					{
						qstp_packet_header_serialize(&resp, sbuf);
						slen = qsc_socket_send(&cns->target, sbuf, KEX_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

						if (slen == KEX_CONNECT_RESPONSE_PACKET_SIZE)
						{
							cns->txseq += 1;

							rbuf = qsc_memutils_realloc(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

							if (rbuf != NULL)
							{
								qsc_memutils_clear(rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE);

								rlen = qsc_socket_receive(&cns->target, rbuf, KEX_EXCHANGE_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

								if (rlen == KEX_EXCHANGE_REQUEST_PACKET_SIZE)
								{
									qstp_packet_header_deserialize(rbuf, &reqt);
									reqt.pmessage = rbuf + QSTP_PACKET_HEADER_SIZE;

									qerr = qstp_header_validate(cns, &reqt, qstp_flag_exchange_request, cns->rxseq, KEX_EXCHANGE_REQUEST_MESSAGE_SIZE);

									if (qerr == qstp_error_none)
									{
										qsc_memutils_clear(sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE);

										/* create the exchange response packet */
										qerr = kex_server_exchange_response(kss, cns, &reqt, &resp);

										if (qerr == qstp_error_none)
										{
											qstp_packet_header_serialize(&resp, sbuf);

											slen = qsc_socket_send(&cns->target, sbuf, KEX_EXCHANGE_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);
		
											if (slen == KEX_EXCHANGE_RESPONSE_PACKET_SIZE)
											{
												cns->txseq += 1;
											}
											else
											{
												qerr = qstp_error_transmit_failure;
											}
										}
									}
								}
								else
								{
									qerr = qstp_error_receive_failure;
								}
							}
							else
							{
								qerr = qstp_error_memory_allocation;
							}
						}
						else
						{
							qerr = qstp_error_transmit_failure;
						}
					}

					qsc_memutils_alloc_free(sbuf);
				}
				else
				{
					qerr = qstp_error_memory_allocation;
				}
			}
			else
			{
				qerr = qstp_error_packet_unsequenced;
			}
		}
		else
		{
			qerr = qstp_error_receive_failure;
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		qerr = qstp_error_memory_allocation;
	}

	kex_server_reset(kss);

	if (qerr != qstp_error_none)
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			kex_send_network_error(&cns->target, qerr);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		qstp_connection_state_dispose(cns);
	}

	return qerr;
}
