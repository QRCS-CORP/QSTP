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

#ifndef QSTP_ROOT_H
#define QSTP_ROOT_H

#include "qstpcommon.h"
#include "qstp.h"

/**
 * \file root.h
 * \brief The QSTP Root Security server.
 *
 * \details
 * This header defines functions used by the QSTP Root Security server, which serves as the trust anchor
 * within the Quantum Secure Tunneling Protocol (QSTP). The root server is responsible for managing
 * root certificates and keys, including exporting certificates to persistent storage, generating new
 * root signing keys, printing certificate details, revoking certificates, and signing child certificates.
 * These operations are fundamental for establishing trust between the QSTP root, servers, and clients.
 *
 * \note These functions are internal and non-exportable.
 */

/**
 * \brief Export the root certificate to a file.
 *
 * \details
 * This function writes the given QSTP root certificate to a file at the specified file path.
 * The exported certificate is used for distribution and for verifying the signatures of
 * child certificates in the QSTP system.
 *
 * \param root [const] A pointer to the QSTP root certificate to be exported.
 * \param fpath The output file path where the root certificate will be saved.
 *
 * \return Returns true if the export operation succeeds; otherwise, returns false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_export(const qstp_root_certificate* root, const char* fpath);

/**
 * \brief Generate a new root key.
 *
 * \details
 * This function generates a new QSTP root signing key. It populates the provided root signature key structure
 * with a new key, using the specified issuer name and a validity period (in days). The newly generated root key
 * is used to sign certificates for QSTP servers and clients, thus establishing a chain of trust.
 *
 * \param kset A pointer to the QSTP root signature key structure that will receive the new key.
 * \param issuer The issuer name to be associated with the new root key. The string length must be equal to 
 *        \c QSTP_CERTIFICATE_ISSUER_SIZE.
 * \param exp The number of valid days for the new root key.
 */
QSTP_EXPORT_API void qstp_root_key_generate(qstp_root_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp);

/**
 * \brief Print the root certificate.
 *
 * \details
 * This function prints the details of the QSTP root certificate to the standard output or to a designated
 * logging stream. It is typically used for debugging or verification of the root certificate information.
 *
 * \param root [const] A pointer to the QSTP root certificate.
 */
QSTP_EXPORT_API void qstp_root_certificate_print(const qstp_root_certificate* root);

/**
 * \brief Print a server certificate.
 *
 * \details
 * This function prints the details of a QSTP server certificate, including issuer, serial number,
 * validity period, and cryptographic parameters. It is used for debugging and verifying the server certificate.
 *
 * \param cert [const] A pointer to the QSTP server certificate.
 */
QSTP_EXPORT_API void qstp_root_server_certificate_print(const qstp_server_certificate* cert);

/**
 * \brief Send a certificate revocation request to a client.
 *
 * \details
 * This function sends a certificate revocation request to a client, using the provided root signing key
 * and the certificate serial number that identifies the certificate to be revoked. The request is sent
 * to the specified server IPv4 network address.
 *
 * \param rootkey A pointer to the root signing key.
 * \param serial A pointer to the certificate serial number that should be revoked.
 * \param address A pointer to the IPv4 network address of the target server.
 *
 * \return Returns a value of type \c qstp_errors indicating the result of the revocation request.
 */
QSTP_EXPORT_API qstp_errors qstp_root_certificate_revoke(const uint8_t* rootkey, const uint8_t* serial, const qsc_ipinfo_ipv4_address* address);

/**
 * \brief Sign a child certificate.
 *
 * \details
 * This function signs a child certificate using the provided root certificate and root signing key.
 * The signed certificate is then exported to the file specified by the file path. Signing a child certificate
 * attests to its authenticity and establishes its chain of trust from the root.
 *
 * \param fpath The file path where the signed child certificate will be saved.
 * \param root A pointer to the QSTP root certificate.
 * \param rootkey A pointer to the root signing key.
 *
 * \return Returns true if the certificate signing is successful; otherwise, returns false.
 */
QSTP_EXPORT_API bool qstp_root_sign_certificate(const char* fpath, const qstp_root_certificate* root, const uint8_t* rootkey);

#endif