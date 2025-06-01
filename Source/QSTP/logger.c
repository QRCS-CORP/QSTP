#include "logger.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "stringutils.h"
#include "timestamp.h"

static char m_log_path[QSC_SYSTEM_MAX_PATH] = { 0 };

static void logger_default_path(char* path, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, path);
	qsc_folderutils_append_delimiter(path);
	qsc_stringutils_concat_strings(path, pathlen, QSTP_LOGGER_PATH);
	res = qsc_folderutils_directory_exists(path);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(path);
	}

	if (res == true)
	{
		qsc_folderutils_append_delimiter(path);
		qsc_stringutils_concat_strings(path, pathlen, QSTP_LOGGER_FILE);
	}
}

void qstp_logger_initialize(const char* path)
{
	logger_default_path(m_log_path, QSC_SYSTEM_MAX_PATH);

	if (qstp_logger_exists() == false)
	{
		qsc_memutils_clear(m_log_path, QSC_SYSTEM_MAX_PATH);

		if (path != NULL)
		{
			if (qsc_fileutils_valid_path(path) == true)
			{
				size_t plen;

				plen = qsc_stringutils_string_size(path);
				qsc_memutils_copy(m_log_path, path, plen);
			}
		}

		if (qsc_stringutils_string_size(m_log_path) == 0)
		{
			logger_default_path(m_log_path, QSC_SYSTEM_MAX_PATH);
		}

		qstp_logger_reset();
	}
}

bool qstp_logger_exists(void)
{
	bool res;

	res = qsc_fileutils_valid_path(m_log_path);

	if (res == true)
	{
		res = qsc_fileutils_exists(m_log_path);
	}

	return res;
}

void qstp_logger_print(void)
{
	char buf[QSTP_LOGGING_MESSAGE_MAX] = { 0 };
	size_t lctr;
	size_t mlen;

	lctr = 0;

	if (qstp_logger_exists() == true)
	{
		do
		{
			mlen = qsc_fileutils_read_line(m_log_path, buf, sizeof(buf), lctr);
			++lctr;

			if (mlen > 0)
			{
				qsc_consoleutils_print_line(buf);
				qsc_memutils_clear(buf, mlen);
			}
		} 
		while (mlen > 0);
	}
}

void qstp_logger_read(char* output, size_t otplen)
{
	qsc_mutex mtx;

	if (qstp_logger_exists() == true)
	{
		mtx = qsc_async_mutex_lock_ex();
		qsc_fileutils_safe_read(m_log_path, 0, output, otplen);
		qsc_async_mutex_unlock_ex(mtx);
	}
}

void qstp_logger_reset(void)
{
	char dtm[QSC_TIMESTAMP_STRING_SIZE] = { 0 };
	char msg[QSTP_LOGGING_MESSAGE_MAX] = "Created: ";
	size_t mlen;

	if (qstp_logger_exists() == true)
	{
		qsc_fileutils_erase(m_log_path);
	}
	else
	{
		qsc_fileutils_create(m_log_path);
	}

	qsc_fileutils_write_line(m_log_path, QSTP_LOGGER_HEAD, sizeof(QSTP_LOGGER_HEAD) - 1);
	qsc_timestamp_current_datetime(dtm);
	mlen = qsc_stringutils_concat_strings(msg, sizeof(msg), dtm);
	qsc_fileutils_write_line(m_log_path, msg, mlen);
}

size_t qstp_logger_size(void)
{
	size_t res;

	res = 0;

	if (qstp_logger_exists() == true)
	{
		res = qsc_fileutils_get_size(m_log_path);
	}

	return res;
}

bool qstp_logger_write(const char* message)
{
	char buf[QSTP_LOGGING_MESSAGE_MAX + QSC_TIMESTAMP_STRING_SIZE + 4] = { 0 };
	char dlm[4] = " : ";
	qsc_mutex mtx;
	size_t blen;
	size_t mlen;
	bool res;

	res = qstp_logger_exists();
	mlen = qsc_stringutils_string_size(message);

	if (res == true && mlen <= QSTP_LOGGING_MESSAGE_MAX && mlen > 0)
	{
		qsc_timestamp_current_datetime(buf);
		qsc_stringutils_concat_strings(buf, sizeof(buf), dlm);
		blen = qsc_stringutils_concat_strings(buf, sizeof(buf), message);

		mtx = qsc_async_mutex_lock_ex();
		res = qsc_fileutils_write_line(m_log_path, buf, blen);
		qsc_async_mutex_unlock_ex(mtx);
	}

	return res;
}

#if defined(QSTP_DEBUG_MODE)
bool qstp_logger_test(void)
{
	char buf[4 * QSTP_LOGGING_MESSAGE_MAX] = { 0 };
	char msg1[] = "This is a test message: 1";
	char msg2[] = "This is a test message: 2";
	char msg3[] = "This is a test message: 3";
	char msg4[] = "This is a test message: 4";
	size_t flen;
	size_t mlen;
	bool res;

	(void)mlen;
	mlen = qsc_stringutils_string_size(msg1);
	qstp_logger_initialize(NULL);
	res = qstp_logger_exists();

	if (res == true)
	{
		qstp_logger_write(msg1);
		qstp_logger_write(msg2);
		flen = qstp_logger_size();

		qstp_logger_print();
		qstp_logger_reset();
		flen = qstp_logger_size();

		qstp_logger_write(msg3);
		qstp_logger_write(msg4);
		qstp_logger_print();

		flen = qstp_logger_size();
		qstp_logger_read(buf, flen);
	}

	return res;
}
#endif
