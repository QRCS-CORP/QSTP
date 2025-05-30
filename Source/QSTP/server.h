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

#ifndef QSTP_SERVER_H
#define QSTP_SERVER_H

#include "qstp.h"
#include "rcs.h"
#include "socketserver.h"

/**
 * \file server.h
 * \brief QSTP Server functions
 *
 * \details
 * This header declares functions that implement the server-side operations in the Quantum Secure Messaging Protocol (QSTP).
 * The functions defined here manage the server's lifecycle and connection handling, including key expiration checks,
 * key generation, pausing/resuming the server, and starting the multi-threaded server for both IPv4 and IPv6 networks.
 * These operations ensure that the server can properly authenticate itself, manage its connections, and handle client
 * communications according to the protocol requirements.
 *
 * \note These functions are internal and non-exportable.
 */

/*!
 * \def QSTP_SERVER_PAUSE_INTERVAL
 * \brief The pause interval (in milliseconds) used by the server pause function.
 */
#define QSTP_SERVER_PAUSE_INTERVAL 100

/**
 * \brief Check the expiration status of a server key.
 *
 * \details
 * This function examines the expiration time of a given QSTP server signature key to determine if the key is still valid.
 *
 * \param kset A pointer to the QSTP server signature key to be checked.
 *
 * \return Returns true if the key is valid (i.e., not expired); otherwise, returns false.
 */
QSTP_EXPORT_API bool qstp_server_expiration_check(const qstp_server_signature_key* kset);

/**
 * \brief Generate a new signature key for the server.
 *
 * \details
 * This function generates a new QSTP signature key for the server. It fills in the provided server signature key structure
 * using the specified issuer name and expiration period (in days). The generated key will be used for signing operations
 * in the key exchange and authentication processes.
 *
 * \param kset A pointer to the QSTP server signature key structure to be generated.
 * \param issuer [const] A pointer to the issuer string; its length must match QSTP_CERTIFICATE_ISSUER_SIZE.
 * \param exp The expiration period (in days) for which the key will be valid.
 */
QSTP_EXPORT_API void qstp_server_key_generate(qstp_server_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp);

/**
 * \brief Pause the server, suspending new connection joins.
 *
 * \details
 * This function temporarily suspends the server's listener, preventing new clients from joining.
 * Existing connections are maintained while the server is paused.
 */
QSTP_EXPORT_API void qstp_server_pause(void);

/**
 * \brief Quit the server, closing all active connections.
 *
 * \details
 * This function shuts down the server by closing all active connections and terminating the listener.
 * It is used to gracefully exit the server operation.
 */
QSTP_EXPORT_API void qstp_server_quit(void);

/**
 * \brief Resume the server listener function from a paused state.
 *
 * \details
 * This function resumes the server's listener after it has been paused, allowing new client connections to be accepted.
 */
QSTP_EXPORT_API void qstp_server_resume(void);

/**
 * \brief Start the IPv4 multi-threaded server.
 *
 * \details
 * This function starts the QSTP server on an IPv4 network interface using a multi-threaded model.
 * It listens for incoming client connections on the specified listener socket and uses the provided QSTP
 * private key for authentication and key exchange. The function also accepts callback functions to process
 * incoming data and handle disconnect events.
 *
 * \param source A pointer to the listener server socket.
 * \param kset [const] A pointer to the QSTP server signature key (private key) used for authentication.
 * \param receive_callback A pointer to the callback function for processing incoming data from clients.
 * \param disconnect_callback A pointer to the callback function that is invoked when a client disconnects.
 *
 * \return Returns a value of type \c qstp_errors indicating the outcome of starting the IPv4 server.
 */
QSTP_EXPORT_API qstp_errors qstp_server_start_ipv4(qsc_socket* source,
	const qstp_server_signature_key* kset,
	void (*receive_callback)(qstp_connection_state*, const char*, size_t),
	void (*disconnect_callback)(qstp_connection_state*));

/**
 * \brief Start the IPv6 multi-threaded server.
 *
 * \details
 * This function starts the QSTP server on an IPv6 network interface using a multi-threaded model.
 * It listens for incoming client connections on the specified listener socket and uses the provided QSTP
 * private key for authentication and key exchange. The function also accepts callback functions to process
 * incoming data and handle disconnect events.
 *
 * \param source A pointer to the listener server socket.
 * \param kset [const] A pointer to the QSTP server signature key (private key) used for authentication.
 * \param receive_callback A pointer to the callback function for processing incoming data from clients.
 * \param disconnect_callback A pointer to the callback function that is invoked when a client disconnects.
 *
 * \return Returns a value of type \c qstp_errors indicating the outcome of starting the IPv6 server.
 */
QSTP_EXPORT_API qstp_errors qstp_server_start_ipv6(qsc_socket* source,
	const qstp_server_signature_key* kset,
	void (*receive_callback)(qstp_connection_state*, const char*, size_t),
	void (*disconnect_callback)(qstp_connection_state*));

#endif