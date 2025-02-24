#ifndef QSTP_MASTER_COMMON_H
#define QSTP_MASTER_COMMON_H

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include "../../QSC/QSC/common.h"


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
