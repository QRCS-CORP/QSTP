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

#ifndef QSTP_LOGGER_H
#define QSTP_LOGGER_H

#include "common.h"

/**
 * \file logger.h
 * \brief QSTP logging functions.
 *
 * \details
 * This header defines the internal logging functions for the Quantum Secure Tunneling Protocol (QSTP).
 * These functions provide a basic logging subsystem to record operational events, errors, and diagnostic
 * messages during QSTP execution. The logging system is designed for debugging and monitoring purposes and
 * includes functionality to initialize the log, write messages, read and print the log, reset (clear) the log,
 * and retrieve the current log file size.
 *
 * The logging subsystem uses several defined constants:
 *
 * - \c QSTP_LOGGING_MESSAGE_MAX: Defines the maximum allowed length (in characters) for a single log message.
 * - \c QSTP_LOGGER_PATH: The default directory path where the QSTP log file is stored.
 * - \c QSTP_LOGGER_FILE: The default log filename.
 * - \c QSTP_LOGGER_HEAD: The header string written to the log file at initialization, which typically includes
 *   version information.
 *
 * The logger also includes a built-in manual test (\c qstp_logger_test()) that exercises all of the logging
 * functions to ensure proper operation.
 *
 * \note These functions and constants are internal and non-exportable.
 */

/*!
 * \def QSTP_LOGGING_MESSAGE_MAX
 * \brief Maximum length of a log message.
 *
 * This macro defines the maximum number of characters allowed for a single log message.
 */
#define QSTP_LOGGING_MESSAGE_MAX 256

/*!
 * \var QSTP_LOGGER_PATH
 * \brief Default directory path for QSTP log files.
 *
 * This static constant defines the default directory where the QSTP log file is stored.
 */
static const char QSTP_LOGGER_PATH[] = "QSTP";

/*!
 * \var QSTP_LOGGER_FILE
 * \brief Default log file name.
 *
 * This static constant defines the default filename for the QSTP log file.
 */
static const char QSTP_LOGGER_FILE[] = "qstp.log";

/*!
 * \var QSTP_LOGGER_HEAD
 * \brief Log file header string.
 *
 * This static constant defines the header string that is written to the log file upon initialization.
 * It typically includes the QSTP version information.
 */
static const char QSTP_LOGGER_HEAD[] = "QSTP Version 1.1a";

/*!
 * \brief Test if the log file exists.
 *
 * \details
 * This function checks whether the QSTP log file exists in the configured logging directory.
 *
 * \return Returns true if the log file exists, otherwise false.
 */
bool qstp_logger_exists(void);

/*!
 * \brief Initialize the logger.
 *
 * \details
 * This function initializes the QSTP logging subsystem. It sets the log file path to the provided
 * value and creates the log file if it does not already exist, writing the default header (\c QSTP_LOGGER_HEAD)
 * to the file.
 *
 * \param path A pointer to a null-terminated string specifying the log file path.
 */
void qstp_logger_initialize(const char* path);

/*!
 * \brief Print the log file.
 *
 * \details
 * This function outputs the contents of the QSTP log file to the standard output or a designated debug console.
 * It is useful for real-time debugging and monitoring of log messages.
 */
void qstp_logger_print(void);

/*!
 * \brief Read the log file into a buffer.
 *
 * \details
 * This function reads the contents of the QSTP log file into the provided output array.
 * The caller must ensure that the output buffer is large enough to hold the log contents.
 *
 * \param output A pointer to the buffer where the log contents will be stored.
 * \param otplen The size of the output buffer in bytes.
 */
void qstp_logger_read(char* output, size_t otplen);

/*!
 * \brief Reset the logger.
 *
 * \details
 * This function erases all contents of the QSTP log file, effectively resetting the log.
 * This is useful for clearing old log data before starting a new session or for troubleshooting.
 */
void qstp_logger_reset(void);

/*!
 * \brief Get the size of the log file.
 *
 * \details
 * This function returns the current size (in bytes) of the QSTP log file.
 *
 * \return Returns the size of the log file in bytes.
 */
size_t qstp_logger_size(void);

/*!
 * \brief Write a message to the log file.
 *
 * \details
 * This function appends the provided log message to the QSTP log file. The message should be a null-terminated
 * string and must not exceed \c QSTP_LOGGING_MESSAGE_MAX characters.
 *
 * \param message [const] A pointer to the log message string.
 *
 * \return Returns true if the message was successfully written to the log file; otherwise, false.
 */
bool qstp_logger_write(const char* message);

/*!
 * \brief Run a manual test of the logger functions.
 *
 * \details
 * This function performs a manual test of the QSTP logging subsystem. The test includes:
 *
 * - Checking if the log file exists.
 * - Initializing the logger with a test path.
 * - Writing test messages to the log.
 * - Reading and printing the log contents.
 * - Resetting the log and verifying that the log is cleared.
 *
 * This test ensures that all logging operations (initialization, writing, reading, resetting, and size retrieval)
 * function as expected.
 *
 * \return Returns true if all logger tests pass successfully.
 */
bool qstp_logger_test(void);

#endif