/* uftpd -- the no nonsense (T)FTP server
 *
 * Copyright (c) 2014-2019  Joachim Nilsson <troglobit@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#define SYSLOG_NAMES
#include "uftpd.h"

int uftpd_loglevel = LOG_NOTICE;


#ifndef UFTPD_EMBEDDED
int uftpd_loglvl(char *level)
{
	for (int i = 0; prioritynames[i].c_name; i++) {
		if (string_match(prioritynames[i].c_name, level))
			return prioritynames[i].c_val;
	}

	return atoi(level);
}
#endif

void uftpd_logit(int severity, const char *fmt, ...)
{
	FILE *file;
	va_list args;

	if (uftpd_loglevel == INTERNAL_NOPRI)
		return;

	if (severity > LOG_WARNING)
		file = stdout;
	else
		file = stderr;

	va_start(args, fmt);
#ifndef UFTPD_EMBEDDED
	if (uftpd_do_syslog)
		vsyslog(severity, fmt, args);
	else
#endif
	if (severity <= uftpd_loglevel) {
		if (uftpd_loglevel == LOG_DEBUG)
			fprintf(file, "%d> ", getpid());
		vfprintf(file, fmt, args);
		fflush(file);
	}
	va_end(args);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
