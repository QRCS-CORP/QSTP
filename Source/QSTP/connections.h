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

#ifndef QSTP_CONNECTIONS_H
#define QSTP_CONNECTIONS_H

#include "qstpcommon.h"
#include "qstp.h"

/**
 * \file connections.h
 * \brief The server connection collection.
 *
 * \details
 * This header defines a set of internal functions for managing the QSTP connection collection.
 * The connection collection is an array or list of QSTP connection state objects that represent
 * active or available network connections. These functions provide mechanisms to:
 *
 * - Check the active status of a connection at a given index.
 * - Add a new connection state to the collection.
 * - Retrieve connection states by instance number or by index.
 * - Initialize, clear, reset, and dispose of the entire connection collection.
 * - Determine the number of available connection states and the total size of the collection.
 *
 * Additionally, a self-test function is provided to verify the correct operation of the connection
 * collection management routines. The self-test exercises various operations including addition,
 * retrieval, reset, and disposal of connection state items.
 *
 * \note These functions are internal and non-exportable.
 */

/**
 * \brief Check if a connection in the collection is active.
 *
 * \details
 * This function checks whether the connection state at the specified index in the connection collection
 * is currently marked as active.
 *
 * \param index The index (zero-based) in the connections collection.
 *
 * \return Returns true if the connection at the given index is active; otherwise, returns false.
 */
bool qstp_connections_active(size_t index);

/**
 * \brief Add a new connection state to the collection and mark it as active.
 *
 * \details
 * This function creates a new connection state object, adds it to the connections collection, and sets its
 * status to active. If the collection is full or memory allocation fails, the function returns NULL.
 *
 * \return Returns a pointer to the newly added QSTP connection state, or NULL on failure.
 */
qstp_connection_state* qstp_connections_add(void);

/**
 * \brief Get the number of available (inactive) connection states in the collection.
 *
 * \details
 * This function returns the count of connection state slots in the collection that are currently available
 * for new connections.
 *
 * \return The number of available connection state items.
 */
size_t qstp_connections_available(void);

/**
 * \brief Retrieve a connection state pointer using its instance number.
 *
 * \details
 * This function locates and returns the connection state object corresponding to the provided instance number.
 * The instance number uniquely identifies a connection within the collection.
 *
 * \param instance The unique instance number associated with a connection.
 *
 * \return Returns a pointer to the QSTP connection state if found; otherwise, returns NULL.
 */
qstp_connection_state* qstp_connections_get(uint32_t instance);

/**
 * \brief Initialize the connections collection.
 *
 * \details
 * This function initializes the connection collection by creating an initial set of connection state objects.
 * The \a count parameter specifies the number of connection states to create initially (must be at least one),
 * and the \a maximum parameter defines the maximum capacity of the collection. The maximum must be greater than
 * or equal to the count.
 *
 * \param count The initial number of connection state objects to allocate.
 * \param maximum The maximum number of connection states the collection can hold.
 */
void qstp_connections_initialize(size_t count, size_t maximum);

/**
 * \brief Erase all connection states in the collection.
 *
 * \details
 * This function clears all entries in the connection collection, marking each state as inactive.
 * It does not dispose of the collection itself, but resets its contents so that they may be reused.
 */
void qstp_connections_clear(void);

/**
 * \brief Dispose of the connections collection.
 *
 * \details
 * This function releases all resources allocated for the connections collection and resets its state.
 * It should be called when the collection is no longer needed.
 */
void qstp_connections_dispose(void);

/**
 * \brief Retrieve a connection state pointer by its collection index.
 *
 * \details
 * This function returns the connection state object located at the specified index in the collection.
 * If the index is out of bounds or invalid, the function returns NULL.
 *
 * \param index The index of the connection state within the collection.
 *
 * \return Returns a pointer to the QSTP connection state, or NULL if the index is invalid.
 */
qstp_connection_state* qstp_connections_index(size_t index);

/**
 * \brief Check if the connection collection is full.
 *
 * \details
 * This function checks whether the connection collection has reached its maximum capacity.
 * When the collection is full, no additional connection state objects can be added.
 *
 * \return Returns true if the collection is full; otherwise, false.
 */
bool qstp_connections_full(void);

/**
 * \brief Get the next available connection state.
 *
 * \details
 * This function searches the connection collection for the next available (inactive) connection state
 * and returns a pointer to it. If all connection states are active, the function returns NULL.
 *
 * \return Returns a pointer to the next available QSTP connection state, or NULL if none are available.
 */
qstp_connection_state* qstp_connections_next(void);

/**
 * \brief Reset a connection state in the collection.
 *
 * \details
 * This function resets the connection state identified by the given instance number. Resetting a connection
 * typically clears its data and marks it as inactive so that the slot can be reused.
 *
 * \param instance The unique instance number of the connection to reset.
 */
void qstp_connections_reset(uint32_t instance);

/**
 * \brief Get the total number of connection state objects in the collection.
 *
 * \details
 * This function returns the total size of the connection collection, including both active and inactive states.
 *
 * \return Returns the total number of connection state items in the collection.
 */
size_t qstp_connections_size(void);

/**
 * \brief Run the self-test for the connection collection.
 *
 * \details
 * This function performs a series of tests on the connection collection to verify its proper functioning.
 * The self-test exercises various operations, such as adding new connection states, checking active status,
 * retrieving connection states by index and instance, resetting connections, and ensuring that the reported
 * sizes (available and total) are correct. This helps confirm the robustness and correctness of the connection
 * management routines.
 */
void qstp_connections_self_test(void);

#endif
