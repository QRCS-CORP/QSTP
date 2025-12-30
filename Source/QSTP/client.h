/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
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
 * \brief Send a symmetric key-ratchet request to the remote host.
 *
 * \details
 * This function initiates a symmetric key ratchet process in an ongoing QSTP session. By periodically
 * updating the symmetric session keys, it maintains forward secrecy and ensures that any compromise
 * of past keys does not affect the security of future communications.
 *
 * \param cns A pointer to the current QSTP connection state structure.
 *
 * \return Returns true if the symmetric ratchet request was successfully sent, otherwise false.
 */
QSTP_EXPORT_API bool qstp_send_symmetric_ratchet_request(qstp_connection_state* cns);

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
