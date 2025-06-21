#include "connections.h"
#include "qstpcommon.h"
#include "memutils.h"

/** \cond */
typedef struct qstp_connection_set
{
	qstp_connection_state* conset;
	bool* active;
	size_t maximum;
	size_t length;
} qstp_connection_set;

static qstp_connection_set m_connection_set;
/** \endcond */

bool qstp_connections_active(size_t index)
{
	bool res;

	res = false;

	if (index < m_connection_set.length)
	{
		res = m_connection_set.active[index];
	}

	return res;
}

qstp_connection_state* qstp_connections_add(void)
{
	qstp_connection_state* cns;

	cns = NULL;

	if ((m_connection_set.length + 1U) <= m_connection_set.maximum)
	{
		m_connection_set.conset = qsc_memutils_realloc(m_connection_set.conset, (m_connection_set.length + 1U) * sizeof(qstp_connection_state));
		m_connection_set.active = qsc_memutils_realloc(m_connection_set.active, (m_connection_set.length + 1U) * sizeof(bool));

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(&m_connection_set.conset[m_connection_set.length], sizeof(qstp_connection_state));
			m_connection_set.conset[m_connection_set.length].cid = (uint32_t)m_connection_set.length;
			m_connection_set.active[m_connection_set.length] = true;
			cns = &m_connection_set.conset[m_connection_set.length];
			++m_connection_set.length;
		}
	}

	return cns;
}

size_t qstp_connections_available(void)
{
	size_t count;

	count = 0U;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			++count;
		}
	}
	
	return count;
}

void qstp_connections_clear(void)
{
	qsc_memutils_clear(m_connection_set.conset, sizeof(qstp_connection_state) * m_connection_set.length);

	for (size_t i = 0; i < m_connection_set.length; ++i)
	{
		m_connection_set.active[i] = false;
		m_connection_set.conset[i].cid = (uint32_t)i;
	}
}

void qstp_connections_dispose(void)
{
	if (m_connection_set.conset != NULL)
	{
		qstp_connections_clear();

		if (m_connection_set.conset != NULL)
		{
			qsc_memutils_alloc_free(m_connection_set.conset);
			m_connection_set.conset = NULL;
		}
	}

	if (m_connection_set.active != NULL)
	{
		qsc_memutils_alloc_free(m_connection_set.active);
		m_connection_set.active = NULL;
	}

	m_connection_set.length = 0U;
	m_connection_set.maximum = 0U;
}

qstp_connection_state* qstp_connections_index(size_t index)
{
	qstp_connection_state* res;

	res = NULL;

	if (index < m_connection_set.length)
	{
		res = &m_connection_set.conset[index];
	}

	return res;
}

bool qstp_connections_full(void)
{
	bool res;

	res = true;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.active[i] == false)
		{
			res = false;
			break;
		}
	}

	return res;
}

qstp_connection_state* qstp_connections_get(uint32_t cid)
{
	qstp_connection_state* res;

	res = NULL;

	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			res = &m_connection_set.conset[i];
		}
	}

	return res;
}

void qstp_connections_initialize(size_t count, size_t maximum)
{
	QSTP_ASSERT(count != 0U);
	QSTP_ASSERT(maximum != 0U);
	QSTP_ASSERT(count <= maximum);
	
	if (count != 0U && maximum != 0U && count <= maximum)
	{
		m_connection_set.length = count;
		m_connection_set.maximum = maximum;
		m_connection_set.conset = (qstp_connection_state*)qsc_memutils_malloc(m_connection_set.length * sizeof(qstp_connection_state));
		m_connection_set.active = (bool*)qsc_memutils_malloc(m_connection_set.length * sizeof(bool));

		if (m_connection_set.conset != NULL && m_connection_set.active != NULL)
		{
			qsc_memutils_clear(m_connection_set.conset, m_connection_set.length * sizeof(qstp_connection_state));

			for (size_t i = 0U; i < count; ++i)
			{
				m_connection_set.conset[i].cid = (uint32_t)i;
				m_connection_set.active[i] = false;
			}
		}
	}
}

qstp_connection_state* qstp_connections_next(void)
{
	qstp_connection_state* res;

	res = NULL;

	if (qstp_connections_full() == false)
	{
		for (size_t i = 0U; i < m_connection_set.length; ++i)
		{
			if (m_connection_set.active[i] == false)
			{
				res = &m_connection_set.conset[i];
				m_connection_set.active[i] = true;
				break;
			}
		}
	}
	else
	{
		res = qstp_connections_add();
	}

	return res;
}

void qstp_connections_reset(uint32_t cid)
{
	for (size_t i = 0U; i < m_connection_set.length; ++i)
	{
		if (m_connection_set.conset[i].cid == cid)
		{
			qsc_memutils_clear(&m_connection_set.conset[i], sizeof(qstp_connection_state));
			m_connection_set.conset[i].cid = (uint32_t)i;
			m_connection_set.active[i] = false;
			break;
		}
	}
}

size_t qstp_connections_size(void)
{
	return m_connection_set.length;
}

#if defined(QSTP_DEBUG_MODE)
void qstp_connections_self_test(void)
{
	qstp_connection_state* xn[20U] = { 0 };
	size_t cnt;
	bool full;

	(void)cnt;
	(void)full;
	qstp_connections_initialize(1U, 10U); /* init with 1 */

	for (size_t i = 1U; i < 10U; ++i)
	{
		xn[i] = qstp_connections_next(); /* init next 9 */
	}

	cnt = qstp_connections_available(); /* expected 0 */
	full = qstp_connections_full(); /* expected true */

	qstp_connections_reset(1U); /* release 5 */
	qstp_connections_reset(3U);
	qstp_connections_reset(5U);
	qstp_connections_reset(7U);
	qstp_connections_reset(9U);

	full = qstp_connections_full(); /* expected false */

	xn[11U] = qstp_connections_next(); /* reclaim 5 */
	xn[12U] = qstp_connections_next();
	xn[13U] = qstp_connections_next();
	xn[14U] = qstp_connections_next();
	xn[15U] = qstp_connections_next();

	full = qstp_connections_full(); /* expected true */

	xn[16U] = qstp_connections_next(); /* should exceed max */

	cnt = qstp_connections_size(); /* expected 10 */

	qstp_connections_clear();
	qstp_connections_dispose();
}
#endif
