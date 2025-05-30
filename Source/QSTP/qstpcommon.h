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

#ifndef QSTP_MASTER_COMMON_H
#define QSTP_MASTER_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "qsccommon.h"

/**
* \file common.h
* \brief QSTP common includes and definitions
* \note These are internal definitions.
*
* \author   John G. Underhill
* \version  1.0
* \date     August 27, 2024
* \contact: john.underhill@protonmail.com
*/

/*!
\def QSTP_DLL_API
* \brief Enables the dll api exports
*/
#if defined(_DLL)
#	define QSTP_DLL_API
#endif
/*!
\def QSTP_EXPORT_API
* \brief The api export prefix
*/
#if defined(QSTP_DLL_API)
#	if defined(QSC_SYSTEM_COMPILER_MSC)
#		if defined(QSTP_DLL_IMPORT)
#			define QSTP_EXPORT_API __declspec(dllimport)
#		else
#			define QSTP_EXPORT_API __declspec(dllexport)
#		endif
#	elif defined(QSC_SYSTEM_COMPILER_GCC)
#		if defined(QSTP_DLL_IMPORT)
#		define QSTP_EXPORT_API __attribute__((dllimport))
#		else
#		define QSTP_EXPORT_API __attribute__((dllexport))
#		endif
#	else
#		if defined(__SUNPRO_C)
#			if !defined(__GNU_C__)
#				define QSTP_EXPORT_API __attribute__ (visibility(__global))
#			else
#				define QSTP_EXPORT_API __attribute__ __global
#			endif
#		elif defined(_MSG_VER)
#			define QSTP_EXPORT_API extern __declspec(dllexport)
#		else
#			define QSTP_EXPORT_API __attribute__ ((visibility ("default")))
#		endif
#	endif
#else
#	define QSTP_EXPORT_API
#endif


#endif
