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

#ifndef QSTP_CLIENT_H
#define QSTP_CLIENT_H

#include "qstp.h"
#include "rcs.h"
#include "socketclient.h"

/**
 * \file client.h
 * \brief QSTP Client functions
 *
 * \details
 * This header defines functions used to implement the client in the Quantum Secure Tunneling Protocol (QSTP).
 * The client connection functions enable a QSTP client to establish a secure connection to a remote QSTP server
 * using the key exchange mechanism. In this process, the client authenticates the server by validating
 * its certificate against a provided root certificate. The functions support both IPv4 and IPv6 network addresses.
 *
 * The key exchange process performed by these functions includes:
 * - Authenticating the server using the provided QSTP root certificate (as the trust anchor) and the server certificate.
 * - Executing the key exchange protocol to establish a secure tunnel.
 * - Invoking callback functions to manage outgoing messages and to process incoming data streams.
 *
 * Upon successful completion, the QSTP connection state is established and returned through the callback functions.
 * The return value is of type \c qstp_errors which indicates the success or failure of the connection attempt.
 */

/**
 * \brief Connect to the remote server using IPv4 and perform the key exchange.
 *
 * \details
 * This function establishes a connection to a remote QSTP server over IPv4 and initiates the key exchange.
 * It authenticates the server by verifying its certificate against the provided root certificate. After successful
 * authentication and key exchange, a secure communication tunnel is established. The function then invokes the
 * provided callback functions: one for managing the outgoing message send loop and another for processing the incoming
 * server data stream.
 *
 * \param root [const] A pointer to the QSTP root certificate, serving as the trust anchor for server authentication.
 * \param cert [const] A pointer to the QSTP server certificate used for authenticating the server.
 * \param address [const] A pointer to the server's IPv4 network address.
 * \param port The QSTP application port number (typically defined by QSTP_SERVER_PORT).
 * \param send_func A pointer to the callback function responsible for the message send loop.
 * \param receive_callback A pointer to the callback function used to process the server's incoming data stream.
 *
 * \return Returns a value of type \c qstp_errors indicating the success or failure of the connection attempt.
 */
QSTP_EXPORT_API qstp_errors qstp_client_connect_ipv4(const qstp_root_certificate* root, 
	const qstp_server_certificate* cert,
	const qsc_ipinfo_ipv4_address* address, uint16_t port, 
	void (*send_func)(qstp_connection_state*), 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t));

/**
 * \brief Connect to the remote server using IPv6 and perform the key exchange.
 *
 * \details
 * This function establishes a connection to a remote QSTP server over IPv6 and initiates the key exchange.
 * The server is authenticated by validating its certificate against the provided QSTP root certificate. Following
 * successful authentication and key exchange, a secure tunnel is established. The provided callback functions are then
 * used to manage the outgoing message send loop and to process incoming server data.
 *
 * \param root [const] A pointer to the QSTP root certificate used as the trust anchor.
 * \param cert [const] A pointer to the QSTP server certificate.
 * \param address [const] A pointer to the server's IPv6 network address.
 * \param port The QSTP application port number (typically defined by QSTP_SERVER_PORT).
 * \param send_func A pointer to the callback function responsible for the message send loop.
 * \param receive_callback A pointer to the callback function used to process the server's incoming data stream.
 *
 * \return Returns a value of type \c qstp_errors representing the outcome of the connection and key exchange.
 */
QSTP_EXPORT_API qstp_errors qstp_client_connect_ipv6(const qstp_root_certificate* root, 
	const qstp_server_certificate* cert,
	const qsc_ipinfo_ipv6_address* address, uint16_t port, 
	void (*send_func)(qstp_connection_state*), 
	void (*receive_callback)(qstp_connection_state*, const char*, size_t));

#endif
