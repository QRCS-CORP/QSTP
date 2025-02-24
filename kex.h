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

#ifndef QSTP_KEX_H
#define QSTP_KEX_H

#include "common.h"
#include "../QSTP/qstp.h"

/**
 * \file kex.h
 * \brief QSTP key exchange functions.
 *
 * \details
 * This header defines internal functions and state structures used for performing the key exchange
 * in the Quantum Secure Tunneling Protocol (QSTP). The key exchange is a one-way process in which the
 * client receives cryptographic parameters from the server that are used to establish a secure tunnel.
 *
 * The key exchange mechanism in QSTP is responsible for:
 * 
 * - Verifying the server's certificate serial number and public verification key.
 * - Validating a session token hash to ensure the integrity of the key exchange.
 * - Establishing an expiration time for the key exchange session.
 *
 * The following state structures are defined:
 *
 * - \c qstp_kex_client_state: Used by the client during the key exchange, it stores the session token hash,
 *   the server certificate serial number, the server's asymmetric signature verification key, and an expiration timestamp.
 *
 * - \c qstp_kex_server_state: Used by the server during the key exchange, it holds pointers to the server's
 *   private and public asymmetric cipher keys, a certificate serial number (serving as the key identity), a session
 *   token hash, the server's private signing key, the local public verification key, and an expiration timestamp.
 *
 * The following internal (non-exportable) functions are declared:
 *
 * - \c qstp_kex_server_key_exchange: Executes the server-side operations of the key exchange by processing
 *   the client's request, verifying the cryptographic parameters, and updating the connection state.
 *
 * - \c qstp_kex_client_key_exchange: Executes the client-side operations of the key exchange by processing
 *   the server's response, extracting the cryptographic parameters, and ensuring the key exchange completes successfully.
 *
 * \note These functions and structures are internal to QSTP and are not part of the public API.
 */

/*!
 * \struct qstp_kex_client_state
 * \brief The QSTP client state structure.
 *
 * \details
 * This structure holds the state information for a client engaged in a key exchange.
 * It contains:
 *
 * - \c schash: The session token hash used to verify the integrity of the key exchange.
 * - \c serial: The server certificate serial number, used to authenticate the server.
 * - \c verkey: The server's asymmetric signature verification key.
 * - \c expiration: The expiration time (in seconds from the epoch) that indicates the validity period of the key exchange.
 */
typedef struct qstp_kex_client_state
{
	uint8_t schash[QSTP_CERTIFICATE_HASH_SIZE];				/*!< The session token hash */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];			/*!< The server certificate serial number */
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< The server asymmetric signature verification-key */
	uint64_t expiration;									/*!< The expiration time in seconds from epoch */
} qstp_kex_client_state;

/*!
 * \struct qstp_kex_server_state
 * \brief The QSTP server state structure.
 *
 * \details
 * This structure holds the state information for a server participating in a key exchange.
 * It includes:
 *
 * - \c prikey: A pointer to the server's private key for the asymmetric cipher.
 * - \c pubkey: A pointer to the server's public key for the asymmetric cipher.
 * - \c serial: The certificate serial number acting as the key identity.
 * - \c schash: The session token hash used to secure the key exchange.
 * - \c sigkey: The server's private signing key used for signing key exchange data.
 * - \c verkey: The local asymmetric signature verification key.
 * - \c expiration: The expiration time (in seconds from the epoch) for the key exchange session.
 */
typedef struct qstp_kex_server_state
{
	uint8_t* prikey;												/*!< Pointer to the asymmetric cipher private key */
	uint8_t* pubkey;												/*!< Pointer to the asymmetric cipher public key */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];					/*!< The key identity string (certificate serial number) */
	uint8_t schash[QSTP_CERTIFICATE_HASH_SIZE];						/*!< The session token hash */
	uint8_t sigkey[QSTP_ASYMMETRIC_SIGNING_KEY_SIZE];				/*!< The asymmetric signature signing key */
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE];			/*!< The local asymmetric signature verification key */
	uint64_t expiration;											/*!< The expiration time in seconds from epoch */
} qstp_kex_server_state;

/*!
 * \brief Run the network server version of the key exchange.
 *
 * \details
 * This internal function performs the server-side key exchange. It processes the client's key exchange
 * request by using the server key exchange state. The function validates the received session token hash,
 * certificate serial number, and updates the QSTP connection state accordingly.
 *
 * \note This is an internal non-exportable API.
 *
 * \param kss A pointer to the server key exchange state structure (\c qstp_kex_server_state).
 * \param cns A pointer to the QSTP connection state structure.
 *
 * \return Returns a value of type \c qstp_errors indicating the outcome of the key exchange.
 */
qstp_errors qstp_kex_server_key_exchange(qstp_kex_server_state* kss, qstp_connection_state* cns);

/*!
 * \brief Run the network client version of the key exchange.
 *
 * \details
 * This internal function executes the client-side key exchange. It processes the response from the server,
 * extracts the session token hash, server certificate serial number, and the server's public verification key,
 * and verifies the expiration timestamp to ensure the key exchange is valid.
 *
 * \note This is an internal non-exportable API.
 *
 * \param kcs A pointer to the client key exchange state structure (\c qstp_kex_client_state).
 * \param cns A pointer to the QSTP connection state structure.
 *
 * \return Returns a value of type \c qstp_errors indicating the success or failure of the key exchange.
 */
qstp_errors qstp_kex_client_key_exchange(qstp_kex_client_state* kcs, qstp_connection_state* cns);

#endif

