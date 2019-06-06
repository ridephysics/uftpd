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

#ifndef UFTPD_H_
#define UFTPD_H_

#ifdef UFTPD_PRIVATE

#ifndef UFTPD_EMBEDDED
#include "config.h"
#endif

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <libgen.h>
#include <limits.h>
#include <locale.h>
#include <netdb.h>
#include <netinet/in.h>
#include <pwd.h>
#include <sched.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>		/*  PRIu64/PRI64, etc. for stdint.h types */
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>		/* isset(), setbit(), etc. */
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifdef UFTPD_EMBEDDED
#ifdef ESP_PLATFORM
#include <esp_log.h>

#define	LOG_ERR ESP_LOG_ERROR
#define	LOG_WARNING ESP_LOG_WARN
#define	LOG_NOTICE ESP_LOG_INFO
#define	LOG_INFO ESP_LOG_INFO
#define	LOG_DEBUG ESP_LOG_DEBUG

#else
#define	LOG_EMERG	0	/* system is unusable */
#define	LOG_ALERT	1	/* action must be taken immediately */
#define	LOG_CRIT	2	/* critical conditions */
#define	LOG_ERR		3	/* error conditions */
#define	LOG_WARNING	4	/* warning conditions */
#define	LOG_NOTICE	5	/* normal but significant condition */
#define	LOG_INFO	6	/* informational */
#define	LOG_DEBUG	7	/* debug-level messages */

#define	INTERNAL_NOPRI	0x10	/* the "no priority" priority */
#endif

#define VERSION "2.8"

#include <utime.h>
#include <newlib_ext.h>
#else
#include <syslog.h>
#endif

#include <uev/uev.h>
#include <lite/lite.h>

#define FTP_DEFAULT_PORT  21
#define FTP_SERVICE_NAME  "ftp"
#define FTP_PROTO_NAME    "tcp"

#define TFTP_DEFAULT_PORT 69
#define TFTP_SERVICE_NAME "tftp"
#define TFTP_PROTO_NAME   "udp"

#define FTP_DEFAULT_USER  "ftp"
#define FTP_DEFAULT_HOME  "/srv/ftp"

#define BUFFER_SIZE       BUFSIZ

/* This is a stupid server, it doesn't expect >3 min inactivity */
#define INACTIVITY_TIMER  180 * 1000

/* TFTP Packet Types (New) */
#define OACK              06	/* option acknowledgement */

/* TFTP Minimum segment size, specific to uftpd */
#define MIN_SEGSIZE       32

#define UFTPD_LOG_TAG "uftpd"

#ifdef ESP_PLATFORM
#define _uftpd_logit(severity, tag, fmt, args...) \
	ESP_LOG_LEVEL(severity, tag, fmt, ##args)
#else
#define _uftpd_logit(severity, tag, fmt, args...) \
	uftpd_logit(severity, fmt, ##args)
#endif

#define LOGIT(severity, code, fmt, args...)				\
	do {								\
		if (code)						\
			_uftpd_logit(severity, UFTPD_LOG_TAG, fmt ". Error %d: %s%s",		\
			      ##args, code, strerror(code),		\
			      uftpd_do_syslog ? "" : "\n");			\
		else							\
			_uftpd_logit(severity, UFTPD_LOG_TAG, fmt "%s", ##args,		\
			      uftpd_do_syslog ? "" : "\n");			\
	} while (0)
#define ERR(code, fmt, args...)  LOGIT(LOG_ERR, code, fmt, ##args)
#define WARN(code, fmt, args...) LOGIT(LOG_WARNING, code, fmt, ##args)
#define LOG(fmt, args...)        LOGIT(LOG_NOTICE, 0, fmt, ##args)
#define INFO(fmt, args...)       LOGIT(LOG_INFO, 0, fmt, ##args)
#define DBG(fmt, args...)        LOGIT(LOG_DEBUG, 0, fmt, ##args)

#ifndef UFTPD_EMBEDDED
extern char *uftpd_home;		/* Server root/home directory       */
extern int   uftpd_inetd;             /* Bool: conflicts with daemonize   */
extern int   uftpd_chrooted;		/* Bool: are we chrooted?           */
extern struct passwd *uftpd_pw;       /* FTP user's passwd entry          */
#endif
extern char *uftpd_prognm;
extern int   uftpd_loglevel;
extern int   uftpd_do_syslog;         /* Bool: False at daemon start      */

typedef struct tftphdr tftp_t;

typedef struct {
	int sd;
	int type;

	char cwd[PATH_MAX];

	struct sockaddr_storage server_sa;
	struct sockaddr_storage client_sa;

	char serveraddr[INET_ADDRSTRLEN];
	char clientaddr[INET_ADDRSTRLEN];

	/* Event loop context and session watchers */
	uev_t      io_watcher, data_watcher, timeout_watcher;
	uev_ctx_t *ctx;

	/* Session buffer */
	char    *buf;		/* Pointer to segment buffer */
	size_t   bufsz;		/* Size of buf */

	char     facts[10];
	char     pending; 	/* Pending op: LIST, RETR, STOR */
	char     list_mode;	/* Current LIST mode */
	char    *file;	        /* Current file name to fetch */
	off_t    offset;	/* Offset in current file, for REST */
	FILE    *fp;		/* Current file in operation */
	int      i;		/* i of d_num in 'd' */
	int      d_num;		/* Number of entries in 'd' */
	struct dirent **d;	/* Current directory in LIST op */
	struct timeval tv;	/* Progress indicator */

	/* TFTP */
	tftp_t  *th;		/* Same as buf, only as tftp_t */
	size_t   segsize;	/* SEGSIZE, or per session negotiated */
	int      timeout;	/* INACTIVITY_TIMER, or per session neg. */
	uint32_t tftp_options;	/* %1:blksize */

	/* User credentials */
	char name[20];
	char pass[20];

	/* PASV */
	int data_sd;
	int data_listen_sd;

	/* PORT */
	char data_address[INET_ADDRSTRLEN];
	int  data_port;
} ctrl_t;

ctrl_t *uftpd_new_session(uev_ctx_t *ctx, int sd, int *rc);
int     uftpd_del_session(ctrl_t *ctrl, int isftp);

int     uftpd_ftp_session(uev_ctx_t *ctx, int client);
int     uftpd_tftp_session(uev_ctx_t *ctx, int client);

char   *uftpd_compose_path(ctrl_t *ctrl, char *path);
char   *uftpd_compose_abspath(ctrl_t *ctrl, char *path);
int     uftpd_set_nonblock(int fd);
int     uftpd_open_socket(int port, int type, char *desc);
void    uftpd_convert_address(struct sockaddr_storage *ss, char *buf, size_t len);
int     uftpd_poll_write(int fd, int timeout_ms);

#ifndef UFTPD_EMBEDDED
int     uftpd_loglvl(char *level);
#endif
void    uftpd_logit(int severity, const char *fmt, ...);

#endif /* UFTPD_PRIVATE */

int     uftpd_start(uev_ctx_t *ctx);

#endif  /* UFTPD_H_ */

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
