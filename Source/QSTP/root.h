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
 * \param root: [const] A pointer to the QSTP root certificate to be exported.
 * \param fpath: The output file path where the root certificate will be saved.
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
 * \param kset: A pointer to the QSTP root signature key structure that will receive the new key.
 * \param issuer: [const] The issuer name to be associated with the new root key. The string length must be equal to \c QSTP_CERTIFICATE_ISSUER_SIZE.
 * \param exp: The number of valid days for the new root key.
 */
QSTP_EXPORT_API void qstp_root_key_generate(qstp_root_signature_key* kset, const char issuer[QSTP_CERTIFICATE_ISSUER_SIZE], uint32_t exp);

/**
 * \brief Print the root certificate.
 *
 * \details
 * This function prints the details of the QSTP root certificate to the standard output or to a designated
 * logging stream. It is typically used for debugging or verification of the root certificate information.
 *
 * \param root: [const] A pointer to the QSTP root certificate.
 */
QSTP_EXPORT_API void qstp_root_certificate_print(const qstp_root_certificate* root);

#if defined(QSTP_EXTERNAL_SIGNED_ROOT)
/*!
 * \brief Sign the root certificate using the signature scheme signing function.
 * 
 * \details The signing signature scheme must be the same type (ML-DSA or SPH-DSA) and parameter set as the
 * root signature scheme, a mismatch will cause signing failure.
 * 
 * \param root: A pointer to the root certificate.
 * \param authority: Signing authority identity
 * \param keyid: Authority key identity linkage
 * \param csalgorithm: Signature suite used by external authority
 * \param scheme_sign: A pointer to the signature scheme signing function.
 * Note: The signature scheme must be either ML-DSA or SPH-DSA, and the parameter set must match the QSC library enabled parameters.
 *
 * \return Returns true if the certificate is signed; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_external_sign(qstp_root_certificate* root, char authority[QSTP_CERTIFICATE_ISSUER_SIZE],
	uint8_t keyid[QSTP_CERTIFICATE_SERIAL_SIZE], qstp_configuration_sets csalgorithm, uint8_t* sigkey,
	bool (*scheme_sign)(uint8_t*, size_t*, const uint8_t*, size_t, const uint8_t*, bool (*rng_generate)(uint8_t*, size_t)));
#endif

/**
 * \brief Print a server certificate.
 *
 * \details
 * This function prints the details of a QSTP server certificate, including issuer, serial number,
 * validity period, and cryptographic parameters. It is used for debugging and verifying the server certificate.
 *
 * \param cert: [const] A pointer to the QSTP server certificate.
 */
QSTP_EXPORT_API void qstp_root_server_certificate_print(const qstp_server_certificate* cert);

/**
 * \brief Sign a child certificate.
 *
 * \details
 * This function signs a child certificate using the provided root certificate and root signing key.
 * The signed certificate is then exported to the file specified by the file path. Signing a child certificate
 * attests to its authenticity and establishes its chain of trust from the root.
 *
 * \param fpath: [const] The file path where the signed child certificate will be saved.
 * \param root: [const] A pointer to the QSTP root certificate.
 * \param rootkey: [const] A pointer to the root signing key.
 *
 * \return Returns true if the certificate signing is successful; otherwise, returns false.
 */
QSTP_EXPORT_API bool qstp_root_sign_certificate(const char* fpath, const qstp_root_certificate* root, const uint8_t* rootkey);

#if defined(QSTP_DEBUG_MODE)
/**
 * \brief Tests the root certificate signing functionality.
 *
 * \return Returns true on success; otherwise, returns false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_signing_test();
#endif

#endif
