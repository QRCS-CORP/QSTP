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

#ifndef QSTP_H
#define QSTP_H

#include "common.h"
#include "../../QSC/QSC/socketbase.h"
#include "../../QSC/QSC/rcs.h"
#include "../../QSC/QSC/sha3.h"
/**
 * \file qstp.h
 * \brief QSTP support header
 *
 * \details
 * This header file defines common parameters, macros, enumerations, type definitions, and function
 * prototypes used by the QSTP (Quantum Secure Tunneling Protocol) client and server implementations.
 *
 * QSTP is designed to provide a complete cryptographic protocol for secure tunneling by integrating
 * post-quantum key exchange, authenticated encryption, and certificate-based authentication.
 * The protocol utilizes various asymmetric cryptographic primitive sets (e.g., Kyber, McEliece, Dilithium, Sphincs+)
 * which are configured in the QSC library's common.h file. For maximum security, the McEliece/SPHINCS+ set is recommended;
 * for a balance of performance and security, the Dilithium/Kyber or Dilithium/McEliece sets are advised.
 *
 * \par Recommended Parameter Sets:
 * - Kyber-S1, Dilithium-S1
 * - Kyber-S3, Dilithium-S3
 * - Kyber-S5, Dilithium-S5
 * - Kyber-S6, Dilithium-S5
 * - McEliece-S1, Dilithium-S1(f,s)
 * - McEliece-S3, Dilithium-S3(f,s)
 * - McEliece-S5, Dilithium-S5(f,s)
 * - McEliece-S6, Dilithium-S5(f,s)
 * - McEliece-S1, Sphincs-S1(f,s)
 * - McEliece-S3, Sphincs-S3(f,s)
 * - McEliece-S5, Sphincs-S5(f,s)
 * - McEliece-S6, Sphincs-S5(f,s)
 * - McEliece-S7, Sphincs-S6(f,s)
 *
 * \par Additional Notes:
 * When using the McEliece/SPHINCS+ options in Visual Studio, it may be necessary to increase the maximum
 * stack size (e.g., to 200KB) to accommodate the larger key sizes.
 *
 * The parameter sets used by QSTP are selected in the QSC library (via libraries/common.h) at their library defaults.
 * A true 512-bit security level can be achieved by selecting the McEliece/SPHINCS+ parameter and configuring SPHINCS+
 * to one of the 512-bit options.
 */

/*!
 * \def QSTP_CONFIG_DILITHIUM_KYBER
 * \brief Sets the asymmetric cryptographic primitive-set to Dilithium/Kyber.
 */
#define QSTP_CONFIG_DILITHIUM_KYBER

///*!
//* \def QSTP_CONFIG_DILITHIUM_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Dilithium/McEliece.
//*/
//#define QSTP_CONFIG_DILITHIUM_MCELIECE

///*!
//* \def QSTP_CONFIG_SPHINCS_MCELIECE
//* \brief Sets the asymmetric cryptographic primitive-set to Sphincs+/McEliece, default is Dilithium/Kyber.
//* Note: You may have to increase the stack reserve size on both projects, as McEliece and Sphincs+ use many resources.
//*/
//#define QSTP_CONFIG_SPHINCS_MCELIECE

#if defined(QSTP_CONFIG_DILITHIUM_KYBER)
#	include "../../QSC/QSC/dilithium.h"
#	include "../../QSC/QSC/kyber.h"
#elif defined(QSTP_CONFIG_DILITHIUM_MCELIECE)
#	include "../../QSC/QSC/dilithium.h"
#	include "../../QSC/QSC/mceliece.h"
#elif defined(QSTP_CONFIG_SPHINCS_MCELIECE)
#	include "../../QSC/QSC/sphincsplus.h"
#	include "../../QSC/QSC/mceliece.h"
#else
#	error Invalid parameter set!
#endif

/* 
 * Valid parameter sets:
 *   McEliece-S1, Dilithium-S1(f,s)
 *   McEliece-S3, Dilithium-S3(f,s)
 *   McEliece-S5, Dilithium-S5(f,s)
 *   McEliece-S6, Dilithium-S5(f,s)
 *   Kyber-S1, Dilithium-S1
 *   Kyber-S3, Dilithium-S3
 *   Kyber-S5, Dilithium-S5
 *   Kyber-S6, Dilithium-S5
 *   McEliece-S1, Sphincs-S1(f,s)
 *   McEliece-S3, Sphincs-S3(f,s)
 *   McEliece-S5, Sphincs-S5(f,s)
 *   McEliece-S6, Sphincs-S5(f,s)
 *   McEliece-S7, Sphincs-S6(f,s)
 */

/*!
 * \def QSTP_PROTOCOL_SET_SIZE
 * \brief The size of the protocol configuration string.
 */
#define QSTP_PROTOCOL_SET_SIZE 42

/*!
 * \enum qstp_configuration_sets
 * \brief The MPDC algorithm configuration sets.
 */
QSTP_EXPORT_API typedef enum qstp_configuration_sets
{
	qstp_configuration_set_none = 0x00,											/*!< No algorithm identifier is set */
	qstp_configuration_set_dilithium1_kyber1_rcs256_shake256 = 0x01,			/*!< The Dilithium-S1/Kyber-S1/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium3_kyber3_rcs256_shake256 = 0x02,			/*!< The Dilithium-S3/Kyber-S3/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium5_kyber5_rcs256_shake256 = 0x03,			/*!< The Dilithium-S5/Kyber-S5/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium5_kyber6_rcs512_shake512 = 0x04,			/*!< The Dilithium-S5/Kyber-S6/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium1_mceliece1_rcs256_shake256 = 0x05,			/*!< The Dilithium-S1/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium3_mceliece3_rcs256_shake256 = 0x06,			/*!< The Dilithium-S3/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium5_mceliece5_rcs256_shake256 = 0x07,			/*!< The Dilithium-S5/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium5_mceliece6_rcs256_shake256 = 0x08,			/*!< The Dilithium-S5/McEliece-S6/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_dilithium5_mceliece7_rcs256_shake256 = 0x09,			/*!< The Dilithium-S5/McEliece-S7/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256 = 0x0A,		/*!< The SPHINCS+-S1F/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256 = 0x0B,		/*!< The SPHINCS+-S1S/McEliece-S1/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256 = 0x0C,		/*!< The SPHINCS+-S3F/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256 = 0x0D,		/*!< The SPHINCS+-S3S/McEliece-S3/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256 = 0x0E,		/*!< The SPHINCS+-S5F/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256 = 0x0F,		/*!< The SPHINCS+-S5S/McEliece-S5a/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256 = 0x10,		/*!< The SPHINCS+-S5F/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256 = 0x11,		/*!< The SPHINCS+-S5S/McEliece-S5b/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256 = 0x12,		/*!< The SPHINCS+-S5F/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
	qstp_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256 = 0x13,		/*!< The SPHINCS+-S5S/McEliece-S5c/RCS-256/SHAKE-256 algorithm set */
} qstp_configuration_sets;

#if defined(QSTP_CONFIG_DILITHIUM_MCELIECE)

	/*!
	 * \def qstp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair using McEliece.
	 */
#	define qstp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qstp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the McEliece asymmetric cipher.
	 */
#	define qstp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qstp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the McEliece asymmetric cipher.
	 */
#	define qstp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qstp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair using Dilithium.
	 */
#	define qstp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qstp_signature_sign
	 * \brief Sign a message using the Dilithium signature scheme.
	 */
#	define qstp_signature_sign qsc_dilithium_sign
	/*!
	 * \def qstp_signature_verify
	 * \brief Verify a message using the Dilithium signature scheme.
	 */
#	define qstp_signature_verify qsc_dilithium_verify

/*!
* \def QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array (McEliece)
*/
#	define QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array (McEliece)
*/
#	define QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array (McEliece)
*/
#	define QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/** \cond */
#	if defined(QSC_DILITHIUM_S1P2544) && defined(QSC_MCELIECE_S1N3488T64)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s1_mceliece-s1_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium1_mceliece1_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S3P4016) && defined(QSC_MCELIECE_S3N4608T96)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s3_mceliece-s3_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium3_mceliece3_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S5N6688T128)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s5_mceliece-s5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium5_mceliece5_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S6N6960T119)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s5_mceliece-s6_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium5_mceliece6_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_MCELIECE_S7N8192T128)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s5_mceliece-s7_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium5_mceliece7_rcs256_shake256;
#	else
#		error the library parameter sets are mismatched!
#	endif
/** \endcond */

#elif defined(QSTP_CONFIG_DILITHIUM_KYBER)

	/*!
	 * \def qstp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair using Kyber.
	 */
#	define qstp_cipher_generate_keypair qsc_kyber_generate_keypair
	/*!
	 * \def qstp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the Kyber asymmetric cipher.
	 */
#	define qstp_cipher_decapsulate qsc_kyber_decapsulate
	/*!
	 * \def qstp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the Kyber asymmetric cipher.
	 */
#	define qstp_cipher_encapsulate qsc_kyber_encapsulate
	/*!
	 * \def qstp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair using Dilithium.
	 */
#	define qstp_signature_generate_keypair qsc_dilithium_generate_keypair
	/*!
	 * \def qstp_signature_sign
	 * \brief Sign a message using the Dilithium signature scheme.
	 */
#	define qstp_signature_sign qsc_dilithium_sign
	/*!
	 * \def qstp_signature_verify
	 * \brief Verify a message using the Dilithium signature scheme.
	 */
#	define qstp_signature_verify qsc_dilithium_verify

/*!
* \def QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the asymmetric cipher-text array (Kyber)
*/
#	define QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_KYBER_CIPHERTEXT_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array (Kyber)
*/
#	define QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_KYBER_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array (Kyber)
*/
#	define QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_KYBER_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_DILITHIUM_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_DILITHIUM_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array (Dilithium)
*/
#	define QSTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_DILITHIUM_SIGNATURE_SIZE)

/** \cond */
#	if defined(QSC_DILITHIUM_S1P2544) && defined(QSC_KYBER_S1P1632)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s1_kyber-s1_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium1_kyber1_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S3P4016) && defined(QSC_KYBER_S3P2400)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s3_kyber-s3_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium3_kyber3_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S5P3168)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium5_kyber5_rcs256_shake256;
#	elif defined(QSC_DILITHIUM_S5P4880) && defined(QSC_KYBER_S6P3936)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "dilithium-s5_kyber-s6_rcs-512_sha3-512";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_dilithium5_kyber6_rcs512_shake512;
#	else
#		error the library parameter sets are mismatched!
#	endif
/** \endcond */

#elif defined(QSTP_CONFIG_SPHINCS_MCELIECE)

	/*!
	 * \def qstp_cipher_generate_keypair
	 * \brief Generate an asymmetric cipher key-pair using McEliece.
	 */
#	define qstp_cipher_generate_keypair qsc_mceliece_generate_keypair
	/*!
	 * \def qstp_cipher_decapsulate
	 * \brief Decapsulate a shared-secret with the McEliece asymmetric cipher.
	 */
#	define qstp_cipher_decapsulate qsc_mceliece_decapsulate
	/*!
	 * \def qstp_cipher_encapsulate
	 * \brief Encapsulate a shared-secret with the McEliece asymmetric cipher.
	 */
#	define qstp_cipher_encapsulate qsc_mceliece_encapsulate
	/*!
	 * \def qstp_signature_generate_keypair
	 * \brief Generate an asymmetric signature key-pair using Sphincs+.
	 */
#	define qstp_signature_generate_keypair qsc_sphincsplus_generate_keypair
	/*!
	 * \def qstp_signature_sign
	 * \brief Sign a message using the Sphincs+ signature scheme.
	 */
#	define qstp_signature_sign qsc_sphincsplus_sign
	/*!
	 * \def qstp_signature_verify
	 * \brief Verify a message using the Sphincs+ signature scheme.
	 */
#	define qstp_signature_verify qsc_sphincsplus_verify

/*!
* \def QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE
* \brief The byte size of the cipher-text array (McEliece)
*/
#	define QSTP_ASYMMETRIC_CIPHER_TEXT_SIZE (QSC_MCELIECE_CIPHERTEXT_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE
* \brief The byte size of the asymmetric cipher private-key array (McEliece)
*/
#	define QSTP_ASYMMETRIC_PRIVATE_KEY_SIZE (QSC_MCELIECE_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE
* \brief The byte size of the asymmetric cipher public-key array (McEliece)
*/
#	define QSTP_ASYMMETRIC_PUBLIC_KEY_SIZE (QSC_MCELIECE_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNING_KEY_SIZE
* \brief The byte size of the asymmetric signature signing-key array (Sphincs+)
*/
#	define QSTP_ASYMMETRIC_SIGNING_KEY_SIZE (QSC_SPHINCSPLUS_PRIVATEKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE
* \brief The byte size of the asymmetric signature verification-key array (Sphincs+)
*/
#	define QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE (QSC_SPHINCSPLUS_PUBLICKEY_SIZE)

/*!
* \def QSTP_ASYMMETRIC_SIGNATURE_SIZE
* \brief The byte size of the asymmetric signature array (Sphincs+)
*/
#	define QSTP_ASYMMETRIC_SIGNATURE_SIZE (QSC_SPHINCSPLUS_SIGNATURE_SIZE)

/** \cond */
#	if defined(QSC_MCELIECE_S1N3488T64) && defined(QSC_SPHINCSPLUS_S1S128SHAKERF)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s1_sphincs-f1_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus1f_mceliece1_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S1N3488T64) && defined(QSC_SPHINCSPLUS_S1S128SHAKERS)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s1_sphincs-s1_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus1s_mceliece1_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S3N4608T96) && defined(QSC_SPHINCSPLUS_S3S192SHAKERF)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s3_sphincs-f3_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus3f_mceliece3_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S3N4608T96) && defined(QSC_SPHINCSPLUS_S3S192SHAKERS)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s3_sphincs-s3_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus3s_mceliece3_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S5N6688T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s5_sphincs-f5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5f_mceliece5_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S5N6688T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s5_sphincs-s5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5s_mceliece5_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S6N6960T119) && defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s6_sphincs-f5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5f_mceliece6_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S6N6960T119) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s6_sphincs-s5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5s_mceliece6_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S7N8192T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERF)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s7_sphincs-f5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5f_mceliece7_rcs256_shake256;
#	elif defined(QSC_MCELIECE_S7N8192T128) && defined(QSC_SPHINCSPLUS_S5S256SHAKERS)
		static const char QSTP_PROTOCOL_SET_STRING[QSTP_PROTOCOL_SET_SIZE] = "mceliece-s7_sphincs-s5_rcs-256_sha3-256";
		static const qstp_configuration_sets QSTP_CONFIGURATION_SET = qstp_configuration_set_sphincsplus5s_mceliece7_rcs256_shake256;
#	else
		/* The library signature scheme and asymmetric cipher parameter sets must be synchronized 
		   to a common security level; s1, s3, s5 or s6. Check the QSC library common.h file for alignment. */
#		error Invalid parameter sets, check the QSC library settings 
#	endif
/** \endcond */

#endif

/*!
 * \def QSTP_ACTIVE_VERSION
 * \brief The QSTP active version.
 */
#define QSTP_ACTIVE_VERSION 1

/*!
 * \def QSTP_CERTIFICATE_ALGORITHM_SIZE
 * \brief The certificate algorithm type field size in bytes.
 */
#define QSTP_CERTIFICATE_ALGORITHM_SIZE 1

/*!
 * \def QSTP_CERTIFICATE_DESIGNATION_SIZE
 * \brief The certificate designation field size in bytes.
 */
#define QSTP_CERTIFICATE_DESIGNATION_SIZE 1

/*!
 * \def QSTP_CERTIFICATE_EXPIRATION_SIZE
 * \brief The length (in bytes) of the certificate expiration date.
 */
#define QSTP_CERTIFICATE_EXPIRATION_SIZE 16

/*!
 * \def QSTP_CERTIFICATE_HASH_SIZE
 * \brief The size in bytes of the certificate hash.
 */
#define QSTP_CERTIFICATE_HASH_SIZE 32

/*!
 * \def QSTP_CERTIFICATE_ISSUER_SIZE
 * \brief The maximum length of the certificate issuer string (including terminator).
 */
#define QSTP_CERTIFICATE_ISSUER_SIZE 32

/*!
 * \def QSTP_CERTIFICATE_LINE_LENGTH
 * \brief The line length for printing the MPDC certificate.
 */
#define QSTP_CERTIFICATE_LINE_LENGTH 64

/*!
 * \def QSTP_CERTIFICATE_DEFAULT_PERIOD
 * \brief The default certificate validity period in milliseconds.
 */
#define QSTP_CERTIFICATE_DEFAULT_PERIOD ((uint64_t)365 * 24 * 60 * 60)

/*!
 * \def QSTP_CERTIFICATE_DEFAULT_DURATION_DAYS
 * \brief The default number of days a public key remains valid.
 */
#define QSTP_CERTIFICATE_DEFAULT_DURATION_DAYS 365

/*!
 * \def QSTP_CERTIFICATE_DEFAULT_DURATION_SECONDS
 * \brief The number of seconds a public key remains valid.
 */
#define QSTP_CERTIFICATE_DEFAULT_DURATION_SECONDS (QSTP_CERTIFICATE_DEFAULT_DURATION_DAYS * 24 * 60 * 60)

/*!
 * \def QSTP_CERTIFICATE_LINE_LENGTH
 * \brief The line length for printing the QSTP public key.
 */
#define QSTP_CERTIFICATE_LINE_LENGTH 64

/*!
 * \def QSTP_CERTIFICATE_MAXIMUM_PERIOD
 * \brief The maximum certificate validity period in milliseconds.
 */
#define QSTP_CERTIFICATE_MAXIMUM_PERIOD (QSTP_CERTIFICATE_DEFAULT_PERIOD * 2)

/*!
 * \def QSTP_CERTIFICATE_MINIMUM_PERIOD
 * \brief The minimum certificate validity period in milliseconds.
 */
#define QSTP_CERTIFICATE_MINIMUM_PERIOD ((uint64_t)1 * 24 * 60 * 60)

/*!
 * \def QSTP_CERTIFICATE_SERIAL_SIZE
 * \brief The length of the certificate serial number field in bytes.
 */
#define QSTP_CERTIFICATE_SERIAL_SIZE 16

/*!
 * \def QSTP_CERTIFICATE_SERIAL_ENCODED_SIZE
 * \brief The length of the hex-encoded certificate serial number string.
 */
#define QSTP_CERTIFICATE_SERIAL_ENCODED_SIZE 32

/*!
 * \def QSTP_CERTIFICATE_SIGNED_HASH_SIZE
 * \brief The size in bytes of the signature and hash field in a certificate.
 */
#define QSTP_CERTIFICATE_SIGNED_HASH_SIZE (QSTP_ASYMMETRIC_SIGNATURE_SIZE + QSTP_CERTIFICATE_HASH_SIZE)

/*!
 * \def QSTP_CERTIFICATE_TIMESTAMP_SIZE
 * \brief The size in bytes of the key expiration timestamp.
 */
#define QSTP_CERTIFICATE_TIMESTAMP_SIZE 8

/*!
 * \def QSTP_CERTIFICATE_VERSION_SIZE
 * \brief The size in bytes of the certificate version field.
 */
#define QSTP_CERTIFICATE_VERSION_SIZE 1

/*!
 * \def QSTP_CONNECTIONS_INIT
 * \brief The initial QSTP connections queue size.
 */
#define QSTP_CONNECTIONS_INIT 1000

/*!
 * \def QSTP_CONNECTIONS_MAX
 * \brief The maximum number of QSTP connections.
 *
 * Calculated based on approximately 5k bytes per connection (3480 for connection state + 1500 for MTU + overhead)
 * on a system with 256GB of DRAM. Can be increased if supported by the hardware.
 */
#define QSTP_CONNECTIONS_MAX 50000

/*!
 * \def QSTP_CONNECTION_MTU
 * \brief The QSTP packet buffer (MTU) size in bytes.
 */
#define QSTP_CONNECTION_MTU 1500

/*!
 * \def QSTP_KEEPALIVE_TIMEOUT
 * \brief The keep alive timeout in milliseconds (2 minutes).
 */
#define QSTP_KEEPALIVE_TIMEOUT (120 * 1000)

/*!
 * \def QSTP_MACTAG_SIZE
 * \brief The MAC tag size in bytes.
 */
#define QSTP_MACTAG_SIZE 32

/*!
 * \def QSTP_NONCE_SIZE
 * \brief The size in bytes of the symmetric cipher nonce.
 */
#define QSTP_NONCE_SIZE 32

/*!
 * \def QSTP_PACKET_ERROR_SEQUENCE
 * \brief The packet error sequence number.
 */
#define QSTP_PACKET_ERROR_SEQUENCE 0xFF00000000000000ULL

/*!
 * \def QSTP_PACKET_ERROR_SIZE
 * \brief The size in bytes of the packet error message.
 */
#define QSTP_PACKET_ERROR_SIZE 1

/*!
 * \def QSTP_PACKET_FLAG_SIZE
 * \brief The size in bytes of the packet flag field.
 */
#define QSTP_PACKET_FLAG_SIZE 1

/*!
 * \def QSTP_PACKET_HEADER_SIZE
 * \brief The size in bytes of the QSTP packet header.
 */
#define QSTP_PACKET_HEADER_SIZE 21

/*!
 * \def QSTP_PACKET_MESSAGE_LENGTH_SIZE
 * \brief The size in bytes of the packet message length field.
 */
#define QSTP_PACKET_MESSAGE_LENGTH_SIZE 4

/*!
 * \def QSTP_PACKET_MESSAGE_MAX
 * \brief The maximum message size (in bytes) used during the key exchange (approximately 1 GB).
 */
#define QSTP_PACKET_MESSAGE_MAX 0x3D090000

/*!
 * \def QSTP_PACKET_REVOCATION_SEQUENCE
 * \brief The packet sequence number used for revocation messages.
 */
#define QSTP_PACKET_REVOCATION_SEQUENCE 0xFFUL

/*!
 * \def QSTP_PACKET_SEQUENCE_SIZE
 * \brief The size in bytes of the packet sequence number.
 */
#define QSTP_PACKET_SEQUENCE_SIZE 8

/*!
 * \def QSTP_PACKET_SEQUENCE_TERMINATOR
 * \brief The packet sequence number that indicates a connection termination.
 */
#define QSTP_PACKET_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \def QSTP_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is considered valid.
 *
 * On networks with a shared (NTP) time source, this may be as low as 1 second. On exterior networks,
 * this value should be adjusted (typically between 30 and 100 seconds) to account for clock differences.
 */
#define QSTP_PACKET_TIME_THRESHOLD 60

/*!
 * \def QSTP_SECRET_SIZE
 * \brief The size in bytes of the shared secret for each channel.
 */
#define QSTP_SECRET_SIZE 32

/*!
 * \def QSTP_CLIENT_PORT
 * \brief The default QSTP client port number.
 */
#define QSTP_CLIENT_PORT 32118

/*!
 * \def QSTP_SERVER_PORT
 * \brief The default QSTP server port number.
 */
#define QSTP_SERVER_PORT 32119

/*!
 * \def QSTP_ROOT_PORT
 * \brief The default QSTP root port number.
 */
#define QSTP_ROOT_PORT 32120

/*!
 * \def QSTP_SYMMETRIC_KEY_SIZE
 * \brief The size in bytes of the Simplex 256-bit symmetric cipher key.
 */
#define QSTP_SYMMETRIC_KEY_SIZE 32

/*!
 * \def QSTP_STORAGE_PATH_MAX
 * \brief The maximum file system path size.
 */
#define QSTP_STORAGE_PATH_MAX 260

/*!
 * \def QSTP_ROOT_CERTIFICATE_SIZE
 * \brief The total length in bytes of the root certificate.
 */
#define QSTP_ROOT_CERTIFICATE_SIZE (QSTP_CERTIFICATE_HASH_SIZE + \
	QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	QSTP_CERTIFICATE_ISSUER_SIZE + \
	QSTP_CERTIFICATE_SERIAL_SIZE + \
	QSTP_CERTIFICATE_EXPIRATION_SIZE + \
	QSTP_CERTIFICATE_ALGORITHM_SIZE + \
	QSTP_CERTIFICATE_VERSION_SIZE)

/*!
 * \def QSTP_ROOT_SIGNATURE_KEY_SIZE
 * \brief The total length in bytes of the root signature key.
 */
#define QSTP_ROOT_SIGNATURE_KEY_SIZE (QSTP_CERTIFICATE_ISSUER_SIZE + \
	QSTP_CERTIFICATE_SERIAL_SIZE + \
	QSTP_ASYMMETRIC_SIGNING_KEY_SIZE + \
	QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	QSTP_CERTIFICATE_EXPIRATION_SIZE + \
	QSTP_CERTIFICATE_ALGORITHM_SIZE + \
	QSTP_CERTIFICATE_VERSION_SIZE)

/*!
 * \def QSTP_SERVER_CERTIFICATE_SIZE
 * \brief The total length in bytes of a server certificate.
 */
#define QSTP_SERVER_CERTIFICATE_SIZE (QSTP_CERTIFICATE_SIGNED_HASH_SIZE + \
	QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	QSTP_CERTIFICATE_ISSUER_SIZE + \
	QSTP_CERTIFICATE_SERIAL_SIZE + \
	QSTP_CERTIFICATE_SERIAL_SIZE + \
	QSTP_CERTIFICATE_EXPIRATION_SIZE + \
	QSTP_CERTIFICATE_ALGORITHM_SIZE + \
	QSTP_CERTIFICATE_DESIGNATION_SIZE + \
	QSTP_CERTIFICATE_VERSION_SIZE)

/*!
 * \def QSTP_SERVER_SIGNATURE_KEY_SIZE
 * \brief The total length in bytes of a server signing key.
 */
#define QSTP_SERVER_SIGNATURE_KEY_SIZE (QSTP_ASYMMETRIC_SIGNING_KEY_SIZE + \
	QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE + \
	QSTP_CERTIFICATE_ISSUER_SIZE + \
	QSTP_CERTIFICATE_HASH_SIZE + \
	QSTP_CERTIFICATE_SERIAL_SIZE + \
	QSTP_CERTIFICATE_EXPIRATION_SIZE + \
	QSTP_CERTIFICATE_ALGORITHM_SIZE + \
	QSTP_CERTIFICATE_DESIGNATION_SIZE + \
	QSTP_CERTIFICATE_VERSION_SIZE)

/** \cond */
#define QSTP_PROTOCOL_SET_DEPTH 12

/* protocol set strings */
static const char QSTP_PARAMETER_STRINGS[QSTP_PROTOCOL_SET_DEPTH][QSTP_PROTOCOL_SET_SIZE] =
{
	"dilithium-s1_kyber-s1_rcs-256_sha3-256",
	"dilithium-s3_kyber-s3_rcs-256_sha3-256",
	"dilithium-s5_kyber-s5_rcs-256_sha3-256",
	"dilithium-s5_kyber-s6_rcs-256_sha3-256",
	"dilithium-s1_mceliece-s1_rcs-256_sha3-256",
	"dilithium-s3_mceliece-s3_rcs-256_sha3-256",
	"dilithium-s5_mceliece-s5_rcs-256_sha3-256",
	"sphincs-1f_mceliece-s1_rcs-256_sha3-256",
	"sphincs-3f_mceliece-s3_rcs-256_sha3-256",
	"sphincs-5f_mceliece-s5_rcs-256_sha3-256",
	"sphincs-5f_mceliece-s6_rcs-256_sha3-256",
	"sphincs-5f_mceliece-s7_rcs-256_sha3-256",
};
/** \endcond */

/* error code strings */
/** \cond */
#define QSTP_MESSAGE_STRING_DEPTH 20
#define QSTP_MESSAGE_STRING_WIDTH 128

static const char QSTP_MESSAGE_STRINGS[QSTP_MESSAGE_STRING_DEPTH][QSTP_MESSAGE_STRING_WIDTH] =
{
	"No configuration was specified.",
	"The socket accept failed.",
	"The listener socket could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server connected to a host.",
	"The socket receive function failed.",
	"The server memory allocation request has failed.",
	"The key exchange has experienced a failure.",
	"The server has disconnected the client.",
	"The server has disconnected the client due to an error.",
	"The server has had a socket level error.",
	"The server has reached the maximum number of connections.",
	"The server listener socket has failed.",
	"The server has run out of socket connections.",
	"The message decryption has failed.",
	"The keepalive function has failed.",
	"The keepalive period has been exceeded",
	"The connection failed or was interrupted.",
	"The function received an invalid request."
};
/** \endcond */

/** \cond */
#define QSTP_ERROR_STRING_DEPTH 30
#define QSTP_ERROR_STRING_WIDTH 128

static const char QSTP_ERROR_STRINGS[QSTP_ERROR_STRING_DEPTH][QSTP_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The socket accept function returned an error",
	"The symmetric cipher had an authentication failure",
	"The keep alive check failed",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The transmission failed at the KEX connection phase",
	"The asymmetric cipher failed to decapsulate the shared secret",
	"The decryption authentication has failed",
	"The transmission failed at the KEX establish phase",
	"The transmission failed at the KEX exchange phase",
	"The public - key hash is invalid",
	"The server has run out of socket connections",
	"The expected input was invalid",
	"The packet flag was unexpected",
	"The keep alive has expired with no response",
	"The decryption authentication has failed",
	"The QSTP public key has expired ",
	"The key identity is unrecognized",
	"The ratchet operation has failed",
	"The listener function failed to initialize",
	"The server has run out of memory",
	"The packet has valid time expired",
	"The packet was received out of sequence",
	"The random generator has failed",
	"The receiver failed at the network layer",
	"The signing function has failed",
	"The transmitter failed at the network layer",
	"The protocol string was not recognized",
	"The expected data could not be verified"
};
/** \endcond */

/*!
 * \enum qstp_messages
 * \brief The logging message enumeration.
 */
QSTP_EXPORT_API typedef enum qstp_messages
{
	qstp_messages_none = 0x00,						/*!< No configuration was specified */
	qstp_messages_accept_fail = 0x01,				/*!< The socket accept failed */
	qstp_messages_listen_fail = 0x02,				/*!< The listener socket could not connect */
	qstp_messages_bind_fail = 0x03,					/*!< The listener socket could not bind to the address */
	qstp_messages_create_fail = 0x04,				/*!< The listener socket could not be created */
	qstp_messages_connect_success = 0x05,			/*!< The server connected to a host */
	qstp_messages_receive_fail = 0x06,				/*!< The socket receive function failed */
	qstp_messages_allocate_fail = 0x07,				/*!< The server memory allocation request has failed */
	qstp_messages_kex_fail = 0x08,					/*!< The key exchange has experienced a failure */
	qstp_messages_disconnect = 0x09,				/*!< The server has disconnected the client */
	qstp_messages_disconnect_fail = 0x0A,			/*!< The server has disconnected the client due to an error */
	qstp_messages_socket_message = 0x0B,			/*!< The server has had a socket level error */
	qstp_messages_queue_empty = 0x0C,				/*!< The server has reached the maximum number of connections */
	qstp_messages_listener_fail = 0x0D,				/*!< The server listener socket has failed */
	qstp_messages_sockalloc_fail = 0x0E,			/*!< The server has run out of socket connections */
	qstp_messages_decryption_fail = 0x0F,			/*!< The message decryption has failed */
	qstp_messages_keepalive_fail = 0x10,			/*!< The keepalive function has failed */
	qstp_messages_keepalive_timeout = 0x11,			/*!< The keepalive period has been exceeded */
	qstp_messages_connection_fail = 0x12,			/*!< The connection failed or was interrupted */
	qstp_messages_invalid_request = 0x13,			/*!< The function received an invalid request */
} qstp_messages;

/*!
 * \enum qstp_errors
 * \brief The QSTP error values.
 */
QSTP_EXPORT_API typedef enum qstp_errors
{
	qstp_error_none = 0x00,							/*!< No error was detected */
	qstp_error_accept_fail = 0x01,					/*!< The socket accept function returned an error */
	qstp_error_authentication_failure = 0x02,		/*!< The symmetric cipher had an authentication failure */
	qstp_error_bad_keep_alive = 0x03,				/*!< The keep alive check failed */
	qstp_error_channel_down = 0x04,					/*!< The communications channel has failed */
	qstp_error_connection_failure = 0x05,			/*!< The device could not make a connection to the remote host */
	qstp_error_connect_failure = 0x06,				/*!< The transmission failed at the KEX connection phase */
	qstp_error_decapsulation_failure = 0x07,		/*!< The asymmetric cipher failed to decapsulate the shared secret */
	qstp_error_decryption_failure = 0x08,			/*!< The decryption authentication has failed */
	qstp_error_establish_failure = 0x09,			/*!< The transmission failed at the KEX establish phase */
	qstp_error_exchange_failure = 0x0A,				/*!< The transmission failed at the KEX exchange phase */
	qstp_error_hash_invalid = 0x0B,					/*!< The public-key hash is invalid */
	qstp_error_hosts_exceeded = 0x0C,				/*!< The server has run out of socket connections */
	qstp_error_invalid_input = 0x0D,				/*!< The expected input was invalid */
	qstp_error_invalid_request = 0x0E,				/*!< The packet flag was unexpected */
	qstp_error_keepalive_expired = 0x0F,			/*!< The keep alive has expired with no response */
	qstp_error_keepalive_timeout = 0x10,			/*!< The decryption authentication has failed */
	qstp_error_key_expired = 0x11,					/*!< The QSTP public key has expired  */
	qstp_error_key_unrecognized = 0x12,				/*!< The key identity is unrecognized */
	qstp_error_keychain_fail = 0x13,				/*!< The ratchet operation has failed */
	qstp_error_listener_fail = 0x14,				/*!< The listener function failed to initialize */
	qstp_error_memory_allocation = 0x15,			/*!< The server has run out of memory */
	qstp_error_message_time_invalid = 0x16,			/*!< The packet has valid time expired */
	qstp_error_packet_unsequenced = 0x17,			/*!< The packet was received out of sequence */
	qstp_error_random_failure = 0x18,				/*!< The random generator has failed */
	qstp_error_receive_failure = 0x19,				/*!< The receiver failed at the network layer */
	qstp_error_signature_failure = 0x1A,			/*!< The signing function has failed */
	qstp_error_transmit_failure = 0x1B,				/*!< The transmitter failed at the network layer */
	qstp_error_unknown_protocol = 0x1C,				/*!< The protocol string was not recognized */
	qstp_error_verify_failure = 0x1D,				/*!< The expected data could not be verified */
} qstp_errors;

/*!
 * \enum qstp_flags
 * \brief The QSTP packet flags.
 */
QSTP_EXPORT_API typedef enum qstp_flags
{
	qstp_flag_none = 0x00,							/*!< No flag was specified */
	qstp_flag_connect_request = 0x01,				/*!< The QSTP key-exchange client connection request flag */
	qstp_flag_connect_response = 0x02,				/*!< The QSTP key-exchange server connection response flag */
	qstp_flag_connection_terminate = 0x03,			/*!< Indicates the connection is to be terminated */
	qstp_flag_encrypted_message = 0x04,				/*!< Indicates the packet contains an encrypted message */
	qstp_flag_exstart_request = 0x05,				/*!< The QSTP key-exchange client exstart request flag */
	qstp_flag_exstart_response = 0x06,				/*!< The QSTP key-exchange server exstart response flag */
	qstp_flag_exchange_request = 0x07,				/*!< The QSTP key-exchange client exchange request flag */
	qstp_flag_exchange_response = 0x08,				/*!< The QSTP key-exchange server exchange response flag */
	qstp_flag_establish_request = 0x09,				/*!< The QSTP key-exchange client establish request flag */
	qstp_flag_establish_response = 0x0A,			/*!< The QSTP key-exchange server establish response flag */
	qstp_flag_keep_alive_request = 0x0B,			/*!< The packet contains a keep alive request */
	qstp_flag_keep_alive_response = 0x0C,			/*!< The packet contains a keep alive response */
	qstp_flag_remote_connected = 0x0E,				/*!< Indicates that the remote host is connected */
	qstp_flag_remote_terminated = 0x0F,				/*!< Indicates that the remote host has terminated the connection */
	qstp_flag_session_established = 0x10,			/*!< Indicates that the key exchange is in the established state */
	qstp_flag_session_establish_verify = 0x11,		/*!< Indicates that the key exchange is in the established verify state */
	qstp_flag_unrecognized_protocol = 0x12,			/*!< The protocol string is not recognized */
	qstp_flag_certificate_revoke = 0x13,			/*!< Indicates a certificate revocation message */
	qstp_flag_transfer_request = 0x14,				/*!< Reserved: Indicates a transfer request */
	qstp_flag_error_condition = 0xFF,				/*!< Indicates that the connection experienced an error */
} qstp_flags;

/*!
 * \enum qstp_network_designations
 * \brief The MPDC device designations.
 */
QSTP_EXPORT_API typedef enum qstp_network_designations
{
	qstp_network_designation_none = 0x00,				/*!< No designation was selected */
	mpdc_network_designation_client = 0x01,				/*!< The device is a client */
	mpdc_network_designation_root = 0x02,				/*!< The device is the DLA (root) */
	mpdc_network_designation_server = 0x03,				/*!< The device is an inter-domain gateway (server) */
	mpdc_network_designation_all = 0xFF,				/*!< All devices on the network */
} qstp_network_designations;

/*!
 * \enum qstp_version_sets
 * \brief The MPDC version sets.
 */
QSTP_EXPORT_API typedef enum qstp_version_sets
{
	qstp_version_set_none = 0x00,						/*!< No version identifier is set */
	qstp_version_set_one_zero = 0x01,					/*!< The 1.0 version identifier */
} qstp_version_sets;

/*!
 * \struct qstp_certificate_expiration
 * \brief Certificate expiration time structure.
 *
 * This structure holds the starting and expiration times (in seconds) for a certificate.
 */
QSTP_EXPORT_API typedef struct qstp_certificate_expiration
{
	uint64_t from;	/*!< The starting time in seconds */
	uint64_t to;	/*!< The expiration time in seconds */
} qstp_certificate_expiration;

/*!
 * \struct qstp_keep_alive_state
 * \brief The QSTP keep alive state structure.
 *
 * This structure tracks the state of keep-alive messages for a connection.
 */
QSTP_EXPORT_API typedef struct qstp_keep_alive_state
{
	qsc_socket target;	/*!< The target socket structure */
	uint64_t etime;		/*!< The keep alive epoch time */
	uint64_t seqctr;	/*!< The keep alive packet sequence counter */
	bool recd;			/*!< The flag indicating if a keep alive response was received */
} qstp_keep_alive_state;

/*!
 * \struct qstp_server_certificate
 * \brief The server certificate structure.
 *
 * This structure represents a server certificate including the signed hash, issuer information,
 * serial numbers, expiration times, and algorithm configuration.
 */
QSTP_EXPORT_API typedef struct qstp_server_certificate
{
	uint8_t csig[QSTP_CERTIFICATE_SIGNED_HASH_SIZE];	/*!< The certificate's signed hash */
	char issuer[QSTP_CERTIFICATE_ISSUER_SIZE];			/*!< The certificate issuer */
	uint8_t rootser[QSTP_CERTIFICATE_SERIAL_SIZE];		/*!< The root certificate's serial number */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];		/*!< The certificate serial number */
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< The serialized public verification key */
	qstp_certificate_expiration expiration;				/*!< The certificate expiration times */
	qstp_configuration_sets algorithm;					/*!< The algorithm configuration identifier */
	qstp_version_sets version;							/*!< The certificate version */
} qstp_server_certificate;

/*!
 * \struct qstp_server_signature_key
 * \brief The QSTP server key structure.
 *
 * This structure holds the server's key information including issuer, certificate hash, serial number,
 * signing and verification keys, expiration times, and algorithm configuration.
 */
QSTP_EXPORT_API typedef struct qstp_server_signature_key
{
	char issuer[QSTP_CERTIFICATE_ISSUER_SIZE];			/*!< The certificate issuer */
	uint8_t schash[QSTP_CERTIFICATE_HASH_SIZE];			/*!< The root/server certificate hash */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];		/*!< The certificate serial number */
	uint8_t sigkey[QSTP_ASYMMETRIC_SIGNING_KEY_SIZE];	/*!< The asymmetric signature signing key */
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE];	/*!< The serialized public verification key */
	qstp_certificate_expiration expiration;				/*!< The certificate expiration times */
	qstp_configuration_sets algorithm;					/*!< The algorithm configuration identifier */
	qstp_version_sets version;							/*!< The certificate version */
} qstp_server_signature_key;

/*!
 * \struct qstp_root_certificate
 * \brief The root certificate structure.
 *
 * This structure represents the root certificate used for signing and trust in the QSTP system.
 */
QSTP_EXPORT_API typedef struct qstp_root_certificate
{
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE]; /*!< The serialized public key */
	char issuer[QSTP_CERTIFICATE_ISSUER_SIZE];			/*!< The certificate issuer text */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];		/*!< The certificate serial number */
	qstp_certificate_expiration expiration;				/*!< The certificate expiration times */
	qstp_configuration_sets algorithm;					/*!< The signature algorithm identifier */
	qstp_version_sets version;							/*!< The certificate version */
} qstp_root_certificate;

/*!
 * \struct qstp_root_signature_key
 * \brief The QSTP root key structure.
 *
 * This structure holds the root signing key information including issuer, serial number,
 * signing key, verification key, expiration times, and algorithm configuration.
 */
QSTP_EXPORT_API typedef struct qstp_root_signature_key
{
	char issuer[QSTP_CERTIFICATE_ISSUER_SIZE];			/*!< The certificate issuer text */
	uint8_t serial[QSTP_CERTIFICATE_SERIAL_SIZE];		/*!< The certificate serial number */
	uint8_t sigkey[QSTP_ASYMMETRIC_SIGNING_KEY_SIZE];	/*!< The asymmetric signature signing key */
	uint8_t verkey[QSTP_ASYMMETRIC_VERIFICATION_KEY_SIZE]; /*!< The serialized public key */
	qstp_certificate_expiration expiration;				/*!< The certificate expiration times */
	qstp_configuration_sets algorithm;					/*!< The signature algorithm identifier */
	qstp_version_sets version;							/*!< The certificate version */
} qstp_root_signature_key;

/*!
 * \struct qstp_network_packet
 * \brief The QSTP network packet structure.
 *
 * This structure encapsulates the header and payload of a QSTP network packet.
 */
QSTP_EXPORT_API typedef struct qstp_network_packet
{
	uint8_t flag;			/*!< The packet flag */
	uint32_t msglen;		/*!< The message length in bytes */
	uint64_t sequence;		/*!< The packet sequence number */
	uint64_t utctime;		/*!< The UTC time when the packet was created (in seconds) */
	uint8_t* pmessage;		/*!< Pointer to the packet's message buffer */
} qstp_network_packet;

/*!
 * \struct qstp_connection_state
 * \brief The QSTP socket connection state structure.
 *
 * This structure maintains the state of an active QSTP connection, including socket information,
 * cipher states for receive and transmit channels, sequence numbers, and connection flags.
 */
QSTP_EXPORT_API typedef struct qstp_connection_state
{
	qsc_socket target;		/*!< The target socket structure */
	qsc_rcs_state rxcpr;	/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;	/*!< The transmit channel cipher state */
	uint64_t rxseq;			/*!< The receive channel packet sequence number */
	uint64_t txseq;			/*!< The transmit channel packet sequence number */
	uint32_t cid;			/*!< The connection instance count */
	qstp_flags exflag;		/*!< The key exchange (KEX) position flag */
	bool receiver;			/*!< Flag indicating if the connection was initialized in listener mode */
} qstp_connection_state;

/* Default key and path names (hidden from documentation) */
/** \cond */
static const char QSTP_CLIENT_DIRECTORY_PATH[] = "Client";
static const char QSTP_ROOT_CERTIFICATE_EXTENSION_NAME[] = ".qrr";
static const char QSTP_ROOT_DIRECTORY_PATH[] = "Root";
static const char QSTP_ROOT_PRIVATE_KEY_NAME[] = "root_secret_key.qsk";
static const char QSTP_ROOT_PUBLIC_CERTIFICATE_NAME[] = "root_public_cert.qrr";
static const char QSTP_SERVER_CERTIFICATE_EXTENSION_NAME[] = ".qrc";
static const char QSTP_SERVER_DIRECTORY_PATH[] = "Server";
static const char QSTP_SERVER_PRIVATE_KEY_NAME[] = "server_secret_key.qsk";
static const char QSTP_SERVER_PUBLIC_CERTIFICATE_NAME[] = "server_public_cert.qrc";
/** \endcond */

/* Public key encoding constants (hidden from documentation) */
/** \cond */
#define QSTP_CERTIFICATE_SEPERATOR_SIZE 1
#define QSTP_CHILD_CERTIFICATE_HEADER_SIZE 54
#define QSTP_CHILD_CERTIFICATE_HASH_PREFIX_SIZE 30
#define QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE 23
#define QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE 9
#define QSTP_CHILD_CERTIFICATE_NAME_PREFIX_SIZE 7
#define QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE 9
#define QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE 14
#define QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13
#define QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 11
#define QSTP_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12
#define QSTP_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE 10
#define QSTP_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE 14
#define QSTP_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE 10
#define QSTP_CHILD_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13
#define QSTP_CHILD_CERTIFICATE_FOOTER_SIZE 52
/** \endcond */

/** \cond */
static const char QSTP_CHILD_CERTIFICATE_HEADER[QSTP_CHILD_CERTIFICATE_HEADER_SIZE] = "------BEGIN QSTP CHILD PUBLIC CERTIFICATE BLOCK------";
static const char QSTP_CHILD_CERTIFICATE_ROOT_HASH_PREFIX[QSTP_CHILD_CERTIFICATE_HASH_PREFIX_SIZE] = "Root Signed Public Key Hash: ";
static const char QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX[QSTP_CHILD_CERTIFICATE_SIGNATURE_KEY_PREFIX_SIZE] = "Public Signature Key: ";
static const char QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX[QSTP_CHILD_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char QSTP_CHILD_CERTIFICATE_NAME_PREFIX[QSTP_CHILD_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX[QSTP_CHILD_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX[QSTP_CHILD_CERTIFICATE_ROOT_SERIAL_PREFIX_SIZE] = "Root Serial: ";
static const char QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX[QSTP_CHILD_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX[QSTP_CHILD_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = "Valid To: ";
static const char QSTP_CHILD_CERTIFICATE_PROTOCOL_PREFIX[QSTP_CHILD_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char QSTP_CHILD_CERTIFICATE_VERSION_PREFIX[QSTP_CHILD_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char QSTP_CHILD_CERTIFICATE_DESIGNATION_PREFIX[QSTP_CHILD_CERTIFICATE_DESIGNATION_PREFIX_SIZE] = "Designation: ";
static const char QSTP_CHILD_CERTIFICATE_ADDRESS_PREFIX[QSTP_CHILD_CERTIFICATE_ADDRESS_PREFIX_SIZE] = "Address: ";
static const char QSTP_CHILD_CERTIFICATE_PUBLICKEY_PREFIX[QSTP_CHILD_CERTIFICATE_PUBLICKEY_PREFIX_SIZE] = "Public Key: ";
static const char QSTP_CHILD_CERTIFICATE_FOOTER[QSTP_CHILD_CERTIFICATE_FOOTER_SIZE] = "------END QSTP CHILD PUBLIC CERTIFICATE BLOCK------";
/** \endcond */

/** \cond */
#define QSTP_ROOT_CERTIFICATE_HEADER_SIZE 53
#define QSTP_ROOT_CERTIFICATE_HASH_PREFIX_SIZE 19
#define QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE 13
#define QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE 9
#define QSTP_ROOT_CERTIFICATE_NAME_PREFIX_SIZE 7
#define QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE 9
#define QSTP_ROOT_CERTIFICATE_FOOTER_SIZE 51
#define QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE 13
#define QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE 11
#define QSTP_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE 12
#define QSTP_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE 10
#define QSTP_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE 18
#define QSTP_ROOT_ACTIVE_VERSION_STRING_SIZE 5
#define QSTP_CERTIFICATE_DEFAULT_DOMAIN_SIZE 5
/** \endcond */

/** \cond */
static const char QSTP_ROOT_CERTIFICATE_HEADER[QSTP_ROOT_CERTIFICATE_HEADER_SIZE] = "------BEGIN QSTP ROOT PUBLIC CERTIFICATE BLOCK------";
static const char QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX[QSTP_ROOT_CERTIFICATE_ISSUER_PREFIX_SIZE] = "Issuer: ";
static const char QSTP_ROOT_CERTIFICATE_NAME_PREFIX[QSTP_ROOT_CERTIFICATE_NAME_PREFIX_SIZE] = "Name: ";
static const char QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX[QSTP_ROOT_CERTIFICATE_SERIAL_PREFIX_SIZE] = "Serial: ";
static const char QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX[QSTP_ROOT_CERTIFICATE_VALID_FROM_PREFIX_SIZE] = "Valid From: ";
static const char QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX[QSTP_ROOT_CERTIFICATE_EXPIRATION_TO_PREFIX_SIZE] = "Valid To: ";
static const char QSTP_ROOT_CERTIFICATE_PROTOCOL_PREFIX[QSTP_ROOT_CERTIFICATE_ALGORITHM_PREFIX_SIZE] = "Algorithm: ";
static const char QSTP_ROOT_CERTIFICATE_VERSION_PREFIX[QSTP_ROOT_CERTIFICATE_VERSION_PREFIX_SIZE] = "Version: ";
static const char QSTP_ROOT_CERTIFICATE_HASH_PREFIX[QSTP_ROOT_CERTIFICATE_HASH_PREFIX_SIZE] = "Certificate Hash: ";
static const char QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX[QSTP_ROOT_CERTIFICATE_PUBLICKEY_PREFIX_SIZE] = "Public Key: ";
static const char QSTP_ROOT_CERTIFICATE_FOOTER[QSTP_ROOT_CERTIFICATE_FOOTER_SIZE] = "------END QSTP ROOT PUBLIC CERTIFICATE BLOCK------";
static const char QSTP_ROOT_CERTIFICATE_DEFAULT_NAME[QSTP_ROOT_CERTIFICATE_DEFAULT_NAME_SIZE] = " Root Certificate";
static const char QSTP_ACTIVE_VERSION_STRING[QSTP_ROOT_ACTIVE_VERSION_STRING_SIZE] = "0x01";
static const char QSTP_CERTIFICATE_DEFAULT_DOMAIN[QSTP_CERTIFICATE_DEFAULT_DOMAIN_SIZE] = "QSTP";
/** \endcond */

/*!
 * \brief Get the configuration enumerator from a string.
 *
 * \param config The configuration string.
 *
 * \return The corresponding configuration set enumerator.
 */
QSTP_EXPORT_API qstp_configuration_sets qstp_configuration_from_string(const char* config);

/*!
 * \brief Get the configuration string from the enumerator.
 *
 * \param cset The configuration set enumerator.
 *
 * \return The configuration set string or NULL if not recognized.
 */
QSTP_EXPORT_API const char* qstp_configuration_to_string(qstp_configuration_sets cset);

/*!
 * \brief Close the network connection between hosts.
 *
 * \param cns A pointer to the QSTP connection state structure.
 * \param err The error code.
 * \param notify If true, notify the remote host that the connection is closing.
 */
QSTP_EXPORT_API void qstp_connection_close(qstp_connection_state* cns, qstp_errors err, bool notify);

/*!
 * \brief Reset the connection state to zero.
 *
 * \param cns A pointer to the QSTP connection state structure.
 */
QSTP_EXPORT_API void qstp_connection_state_dispose(qstp_connection_state* cns);

/*!
 * \brief Decrypt a message from an input packet.
 *
 * \param cns A pointer to the QSTP connection state structure.
 * \param message The output buffer for the decrypted message.
 * \param msglen A pointer to a variable to receive the message length.
 * \param packetin A pointer to the input QSTP network packet.
 *
 * \return Returns the function error state.
 */
QSTP_EXPORT_API qstp_errors qstp_decrypt_packet(qstp_connection_state* cns, uint8_t* message, size_t* msglen, const qstp_network_packet* packetin);

/*!
 * \brief Encrypt a message and build an output packet.
 *
 * \param cns A pointer to the QSTP connection state structure.
 * \param packetout A pointer to the output QSTP network packet.
 * \param message The input message array.
 * \param msglen The length of the message in bytes.
 *
 * \return Returns the function error state.
 */
QSTP_EXPORT_API qstp_errors qstp_encrypt_packet(qstp_connection_state* cns, qstp_network_packet* packetout, const uint8_t* message, size_t msglen);

/*!
 * \brief Return a pointer to a string description of an error code.
 *
 * \param error The QSTP error code.
 *
 * \return Returns a pointer to an error string or NULL.
 */
QSTP_EXPORT_API const char* qstp_error_to_string(qstp_errors error);

/*!
 * \brief Populate a packet header and set its creation time.
 *
 * \param packetout A pointer to the output QSTP network packet.
 * \param flag The packet flag.
 * \param sequence The packet sequence number.
 * \param msglen The length of the message in bytes.
 */
QSTP_EXPORT_API void qstp_header_create(qstp_network_packet* packetout, qstp_flags flag, uint64_t sequence, uint32_t msglen);

/*!
 * \brief Validate a packet header and timestamp.
 *
 * \param cns A pointer to the QSTP connection state structure.
 * \param packetin A pointer to the input QSTP network packet.
 * \param flag The expected packet flag.
 * \param sequence The expected packet sequence number.
 * \param msglen The expected message length.
 *
 * \return Returns the function error state.
 */
QSTP_EXPORT_API qstp_errors qstp_header_validate(qstp_connection_state* cns, const qstp_network_packet* packetin, qstp_flags flag, uint64_t sequence, uint32_t msglen);

/*!
 * \brief Get the error description string for a QSTP logging message.
 *
 * \param emsg The QSTP message enumeration.
 *
 * \return Returns a pointer to the message string or NULL.
 */
QSTP_EXPORT_API const char* qstp_get_error_description(qstp_messages emsg);

/*!
 * \brief Deserialize a byte array into a QSTP packet header.
 *
 * \param header A pointer to the input header byte array.
 * \param packet A pointer to the QSTP network packet to populate.
 */
QSTP_EXPORT_API void qstp_packet_header_deserialize(const uint8_t* header, qstp_network_packet* packet);

/*!
 * \brief Serialize a QSTP packet header into a byte array.
 *
 * \param packet A pointer to the QSTP network packet to serialize.
 * \param header The output header byte array.
 */
QSTP_EXPORT_API void qstp_packet_header_serialize(const qstp_network_packet* packet, uint8_t* header);

/*!
 * \brief Log an error with a message, socket error, and description.
 *
 * \param emsg The QSTP message enumeration.
 * \param err The socket exception enumeration.
 * \param msg The additional descriptive message.
 */
QSTP_EXPORT_API void qstp_log_error(qstp_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
 * \brief Log a QSTP message.
 *
 * \param emsg The QSTP message enumeration.
 */
QSTP_EXPORT_API void qstp_log_message(qstp_messages emsg);

/*!
 * \brief Log a QSTP message with an additional description.
 *
 * \param emsg The QSTP message enumeration.
 * \param msg The additional descriptive message.
 */
QSTP_EXPORT_API void qstp_log_write(qstp_messages emsg, const char* msg);

/*!
 * \brief Clear the state of a QSTP network packet.
 *
 * \param packet A pointer to the QSTP network packet to clear.
 */
QSTP_EXPORT_API void qstp_packet_clear(qstp_network_packet* packet);

/*!
 * \brief Populate a QSTP packet with an error message.
 *
 * \param packet A pointer to the QSTP network packet.
 * \param error The QSTP error code.
 */
QSTP_EXPORT_API void qstp_packet_error_message(qstp_network_packet* packet, qstp_errors error);

/*!
 * \brief Set the local UTC time (in seconds) in a QSTP packet header.
 *
 * \param packet A pointer to the QSTP network packet to update.
 */
QSTP_EXPORT_API void qstp_packet_set_utc_time(qstp_network_packet* packet);

/*!
 * \brief Check if a QSTP packet was received within the valid time threshold.
 *
 * \param packet A pointer to the QSTP network packet.
 *
 * \return Returns true if the packet's UTC time is within the valid threshold; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_packet_time_valid(const qstp_network_packet* packet);

/*!
 * \brief Serialize a QSTP packet into a byte array.
 *
 * \param packet A pointer to the QSTP network packet.
 * \param pstream The output byte stream buffer.
 *
 * \return Returns the size in bytes of the serialized packet.
 */
QSTP_EXPORT_API size_t qstp_packet_to_stream(const qstp_network_packet* packet, uint8_t* pstream);

/*!
 * \brief Compare two root certificates for equivalence.
 *
 * \param a A pointer to the first root certificate.
 * \param b A pointer to the second root certificate.
 *
 * \return Returns true if the certificates are equal; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_compare(const qstp_root_certificate* a, const qstp_root_certificate* b);

/*!
 * \brief Copy an encoded root certificate into a root certificate structure.
 *
 * \param root A pointer to the output root certificate structure.
 * \param enck The encoded root certificate string.
 * \param enclen The length of the encoded certificate.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_decode(qstp_root_certificate* root, const char* enck, size_t enclen);

/*!
 * \brief Deserialize a root certificate from a serialized byte array.
 *
 * \param root A pointer to the output root certificate.
 * \param input A pointer to the serialized root certificate array.
 */
QSTP_EXPORT_API void qstp_root_certificate_deserialize(qstp_root_certificate* root, const uint8_t input[QSTP_ROOT_CERTIFICATE_SIZE]);

/*!
 * \brief Encode a root certificate into a readable string.
 *
 * \param enck The output encoded certificate string.
 * \param enclen The length of the output buffer.
 * \param root A pointer to the root certificate.
 *
 * \return Returns the size in bytes of the encoded certificate string.
 */
QSTP_EXPORT_API size_t qstp_root_certificate_encode(char* enck, size_t enclen, const qstp_root_certificate* root);

/*!
 * \brief Get the size required to encode a root certificate.
 *
 * \return Returns the size in bytes of the encoded root certificate string.
 */
QSTP_EXPORT_API size_t qstp_root_certificate_encoded_size();

/*!
 * \brief Extract the root certificate from a root signature key.
 *
 * \param root The output root certificate.
 * \param kset A pointer to the input root signature key structure.
 */
QSTP_EXPORT_API void qstp_root_certificate_extract(qstp_root_certificate* root, const qstp_root_signature_key* kset);

/*!
 * \brief Compute the hash of a root certificate.
 *
 * \param output The output hash array.
 * \param root A pointer to the root certificate.
 */
QSTP_EXPORT_API void qstp_root_certificate_hash(uint8_t output[QSTP_CERTIFICATE_HASH_SIZE], const qstp_root_certificate* root);

/*!
 * \brief Serialize a root certificate into a byte array.
 *
 * \param output The array that will receive the serialized certificate.
 * \param root A pointer to the root certificate.
 */
QSTP_EXPORT_API void qstp_root_certificate_serialize(uint8_t output[QSTP_ROOT_CERTIFICATE_SIZE], const qstp_root_certificate* root);

/*!
 * \brief Sign a server certificate using the root certificate.
 *
 * \param cert A pointer to the server certificate to sign.
 * \param root A pointer to the root certificate.
 * \param rsigkey A pointer to the root signing key (encoded).
 *
 * \return Returns the size in bytes of the signed certificate.
 */
QSTP_EXPORT_API size_t qstp_root_certificate_sign(qstp_server_certificate* cert, const qstp_root_certificate* root, const uint8_t* rsigkey);

/*!
 * \brief Verify that a server certificate is signed by the root.
 *
 * \param root A pointer to the root certificate.
 * \param cert A pointer to the server certificate.
 *
 * \return Returns true if the certificate is valid; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_verify(const qstp_root_certificate* root, const qstp_server_certificate* cert);

/*!
 * \brief Write a root certificate to a file.
 *
 * \param root A pointer to the root certificate.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_certificate_to_file(const qstp_root_certificate* root, const char* fpath);

/*!
 * \brief Read a root certificate from a file into a root certificate structure.
 *
 * \param root A pointer to the root certificate.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_file_to_certificate(qstp_root_certificate* root, const char* fpath);

/*!
 * \brief Read a root signature key from a file into a root signature key structure.
 *
 * \param kset A pointer to the root signature key structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_file_to_key(qstp_root_signature_key* kset, const char* fpath);

/*!
 * \brief Get the root certificate issuer name.
 *
 * \param issuer The output buffer to receive the issuer string.
 */
QSTP_EXPORT_API void qstp_root_get_issuer(char issuer[QSTP_CERTIFICATE_ISSUER_SIZE]);

/*!
 * \brief Deserialize a root signature key from an encoded array.
 *
 * \param kset A pointer to the output root signature key structure.
 * \param input The input serialized root key array.
 */
QSTP_EXPORT_API void qstp_root_key_deserialize(qstp_root_signature_key* kset, const uint8_t input[QSTP_ROOT_SIGNATURE_KEY_SIZE]);

/*!
 * \brief Write a root signature key to a file.
 *
 * \param kset A pointer to the root signature key structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_root_key_to_file(const qstp_root_signature_key* kset, const char* fpath);

/*!
 * \brief Serialize a root signature key into an encoded array.
 *
 * \param serk The output array for the serialized root key.
 * \param kset A pointer to the root signature key structure.
 */
QSTP_EXPORT_API void qstp_root_key_serialize(uint8_t serk[QSTP_ROOT_SIGNATURE_KEY_SIZE], const qstp_root_signature_key* kset);

/*!
 * \brief Compare two server certificates for equivalence.
 *
 * \param a A pointer to the first server certificate.
 * \param b A pointer to the second server certificate.
 *
 * \return Returns true if the certificates are equivalent; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_server_certificate_compare(const qstp_server_certificate* a, const qstp_server_certificate* b);

/*!
 * \brief Deserialize a server certificate from a serialized byte stream.
 *
 * \param cert A pointer to the server certificate structure to populate.
 * \param input A pointer to the serialized certificate array.
 */
QSTP_EXPORT_API void qstp_server_certificate_deserialize(qstp_server_certificate* cert, const uint8_t input[QSTP_SERVER_CERTIFICATE_SIZE]);

/*!
 * \brief Encode a public server certificate into a readable string.
 *
 * \param enck The output buffer for the encoded certificate string.
 * \param enclen The length of the output buffer.
 * \param cert A pointer to the server certificate.
 *
 * \return Returns the size in bytes of the encoded certificate string.
 */
QSTP_EXPORT_API size_t qstp_server_certificate_encode(char* enck, size_t enclen, const qstp_server_certificate* cert);

/*!
 * \brief Get the size required to encode a server certificate.
 *
 * \return Returns the size in bytes of the encoded certificate string.
 */
QSTP_EXPORT_API size_t qstp_server_certificate_encoded_size();

/*!
 * \brief Extract the server certificate from a server signature key.
 *
 * \param cert The output server certificate.
 * \param kset A pointer to the server signature key structure.
 */
QSTP_EXPORT_API void qstp_server_certificate_extract(qstp_server_certificate* cert, const qstp_server_signature_key* kset);

/*!
 * \brief Compute the hash of a server certificate.
 *
 * \param output The output hash array.
 * \param cert A pointer to the server certificate.
 */
QSTP_EXPORT_API void qstp_server_certificate_hash(uint8_t output[QSTP_CERTIFICATE_HASH_SIZE], const qstp_server_certificate* cert);

/*!
 * \brief Compute a combined hash of the root and server certificates.
 *
 * \param rshash The output hash array.
 * \param root A pointer to the root certificate.
 * \param cert A pointer to the server certificate.
 */
QSTP_EXPORT_API void qstp_server_root_certificate_hash(uint8_t rshash[QSTP_CERTIFICATE_HASH_SIZE], const qstp_root_certificate* root, const qstp_server_certificate* cert);

/*!
 * \brief Serialize a server certificate into a byte array.
 *
 * \param output The output array for the serialized certificate.
 * \param cert A pointer to the server certificate.
 */
QSTP_EXPORT_API void qstp_server_certificate_serialize(uint8_t output[QSTP_SERVER_CERTIFICATE_SIZE], const qstp_server_certificate* cert);

/*!
 * \brief Write a server certificate to a file.
 *
 * \param cert A pointer to the server certificate structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_server_certificate_to_file(const qstp_server_certificate* cert, const char* fpath);

/*!
 * \brief Read a server certificate from a file into a server certificate structure.
 *
 * \param cert A pointer to the server certificate structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_server_file_to_certificate(qstp_server_certificate* cert, const char* fpath);

/*!
 * \brief Read a server signature key from a file into a server key structure.
 *
 * \param kset A pointer to the server signature key structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_server_file_to_key(qstp_server_signature_key* kset, const char* fpath);

/*!
 * \brief Get the server certificate issuer name.
 *
 * \param issuer The output buffer for the issuer string.
 */
QSTP_EXPORT_API void qstp_server_get_issuer(char issuer[QSTP_CERTIFICATE_ISSUER_SIZE]);

/*!
 * \brief Deserialize a server signature key from an encoded array.
 *
 * \param kset A pointer to the output server signature key structure.
 * \param input The input encoded server key array.
 */
QSTP_EXPORT_API void qstp_server_key_deserialize(qstp_server_signature_key* kset, const uint8_t input[QSTP_SERVER_SIGNATURE_KEY_SIZE]);

/*!
 * \brief Serialize a server signature key into a byte array.
 *
 * \param output The output array for the serialized key.
 * \param kset A pointer to the server signature key structure.
 */
QSTP_EXPORT_API void qstp_server_key_serialize(uint8_t output[QSTP_SERVER_SIGNATURE_KEY_SIZE], const qstp_server_signature_key* kset);

/*!
 * \brief Write a server signature key to a file.
 *
 * \param kset A pointer to the server signature key structure.
 * \param fpath The file path.
 *
 * \return Returns true on success; otherwise, false.
 */
QSTP_EXPORT_API bool qstp_server_key_to_file(const qstp_server_signature_key* kset, const char* fpath);

/*!
 * \brief Convert a version string to a version number.
 *
 * \param sver The input version string.
 * \param sverlen The length of the version string.
 *
 * \return Returns the version number as an 8-bit value.
 */
QSTP_EXPORT_API uint8_t qstp_version_from_string(const char* sver, size_t sverlen);

/*!
 * \brief Convert a version number to a hexadecimal string.
 *
 * \param sver The output version string.
 * \param version The version number.
 */
QSTP_EXPORT_API void qstp_version_to_string(char* sver, uint8_t version);

/*!
* \brief Test the root certificate encoding and decoding functions
*
* \return Returns true if the encoding tests succeed
*/
QSTP_EXPORT_API bool qstp_test_root_certificate_encoding(const qstp_root_certificate* root);

/*!
* \brief Test the server certificate encoding and decoding functions
*
* \return Returns true if the encoding tests succeed
*/
QSTP_EXPORT_API bool qstp_test_server_certificate_encoding(const qstp_server_certificate* cert);


#endif
