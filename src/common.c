/* Common methods shared between FTP and TFTP engines
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

#include "uftpd.h"

#ifndef UFTPD_EMBEDDED
int uftpd_chrooted = 0;
#endif

/* Protect against common directory traversal attacks, for details see
 * https://en.wikipedia.org/wiki/Directory_traversal_attack
 *
 * Example:            /srv/ftp/ ../../etc/passwd => /etc/passwd
 *                    .~~~~~~~~ .~~~~~~~~~
 *                   /         /
 * Server dir ------'         /
 * User input ---------------'
 *
 * Forced dir ------> /srv/ftp/etc
 */
char *uftpd_compose_path(ctrl_t *ctrl, char *path)
{
	struct stat st;
	static char rpath[PATH_MAX];
	char *name, *ptr;
	char dir[PATH_MAX] = { 0 };

	strlcpy(dir, ctrl->cwd, sizeof(dir));
	DBG("Compose path from cwd: %s, arg: %s", ctrl->cwd, path ?: "");
	if (!path || !strlen(path))
		goto check;

	if (path) {
		if (path[0] != '/') {
			if (dir[strlen(dir) - 1] != '/')
				strlcat(dir, "/", sizeof(dir));
		}
		strlcat(dir, path, sizeof(dir));
	}

check:
	while ((ptr = strstr(dir, "//")))
		memmove(ptr, &ptr[1], strlen(&ptr[1]) + 1);

#ifndef UFTPD_EMBEDDED
	if (!uftpd_chrooted) {
		size_t len = strlen(uftpd_home);

		DBG("Server path from CWD: %s", dir);
		if (len > 0 && uftpd_home[len - 1] == '/')
			len--;
		memmove(dir + len, dir, strlen(dir) + 1);
		memcpy(dir, uftpd_home, len);
		DBG("Resulting non-chroot path: %s", dir);
	}
#endif

	/*
	 * Handle directories slightly differently, since dirname() on a
	 * directory returns the parent directory.  So, just squash ..
	 */
	if (!stat(dir, &st) && S_ISDIR(st.st_mode)) {
		if (!realpath(dir, rpath))
			return NULL;
	} else {
		/*
		 * Check realpath() of directory containing the file, a
		 * STOR may want to save a new file.  Then append the
		 * file and return it.
		 */
		name = basename(path);
		ptr = dirname(dir);

		memset(rpath, 0, sizeof(rpath));
		if (!realpath(ptr, rpath)) {
			ERR(errno, "Failed realpath(%s)", ptr);
			return NULL;
		}

		if (rpath[1] != 0)
			strlcat(rpath, "/", sizeof(rpath));
		strlcat(rpath, name, sizeof(rpath));
	}

#ifndef UFTPD_EMBEDDED
	if (!uftpd_chrooted && strncmp(dir, uftpd_home, strlen(uftpd_home))) {
		DBG("Failed non-chroot dir:%s vs home:%s", dir, uftpd_home);
		return NULL;
	}
#endif

	return rpath;
}

char *uftpd_compose_abspath(ctrl_t *ctrl, char *path)
{
	char *ptr;
	char cwd[sizeof(ctrl->cwd)];

	if (path && path[0] == '/') {
		strlcpy(cwd, ctrl->cwd, sizeof(cwd));
		memset(ctrl->cwd, 0, sizeof(ctrl->cwd));
	}

	ptr = uftpd_compose_path(ctrl, path);

	if (path && path[0] == '/')
		strlcpy(ctrl->cwd, cwd, sizeof(ctrl->cwd));

	return ptr;
}

int uftpd_set_nonblock(int fd)
{
	int rc;
	int flags;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -1;

	rc = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (rc < 0)
		return -1;

	return 0;
}

int uftpd_open_socket(int port, int type, char *desc)
{
	int sd, err, val = 1;
	socklen_t len = sizeof(struct sockaddr);
	struct sockaddr_in server;

	sd = socket(AF_INET, type, 0);
	if (sd < 0) {
		WARN(errno, "Failed creating %s server socket", desc);
		return -1;
	}

	err = uftpd_set_nonblock(sd);
	if (err != 0) {
		WARN(errno, "Failed making %s server socket non-blocking", desc);
		close(sd);
		return -1;
	}

	err = setsockopt(sd, SOL_SOCKET, SO_REUSEADDR, (char *)&val, sizeof(val));
	if (err != 0)
		WARN(errno, "Failed setting SO_REUSEADDR on %s socket", type == SOCK_DGRAM ? "TFTP" : "FTP");

	memset(&server, 0, sizeof(server));
	server.sin_family      = AF_INET;
	server.sin_addr.s_addr = INADDR_ANY;
	server.sin_port        = htons(port);
	if (bind(sd, (struct sockaddr *)&server, len) < 0) {
		if (EACCES != errno) {
			WARN(errno, "Failed binding to port %d, maybe another %s server is already running", port, desc);
		}
		close(sd);

		return -1;
	}

	if (port && type != SOCK_DGRAM) {
		if (-1 == listen(sd, 20))
			WARN(errno, "Failed starting %s server", desc);
	}

	DBG("Opened socket for port %d", port);

	return sd;
}

void uftpd_convert_address(struct sockaddr_storage *ss, char *buf, size_t len)
{
	switch (ss->ss_family) {
	case AF_INET:
		inet_ntop(ss->ss_family,
			  &((struct sockaddr_in *)ss)->sin_addr, buf, len);
		break;

	case AF_INET6:
		inet_ntop(ss->ss_family,
			  &((struct sockaddr_in6 *)ss)->sin6_addr, buf, len);
		break;
	}
}

/* Inactivity timer, bye bye */
static void inactivity_cb(uev_t *w, void *arg, int events)
{
	uev_ctx_t *ctx = (uev_ctx_t *)arg;

	INFO("Inactivity timer, exiting ...");
	uev_exit(ctx);
}

ctrl_t *uftpd_new_session(uev_ctx_t *ctx, int sd, int *rc)
{
	int err;
	ctrl_t *ctrl = NULL;
#ifndef UFTPD_EMBEDDED
	static int privs_dropped = 0;
#endif

#ifndef UFTPD_EMBEDDED
	if (!uftpd_inetd) {
		pid_t pid = fork();

		if (pid) {
			DBG("Created new client session as PID %d", pid);
			*rc = pid;
			return NULL;
		}

		/*
		 * Set process group to parent, so uftpd can call
		 * killpg() on all of us when it exits.
		 */
		setpgid(0, getppid());
		/* Create new uEv context for the child. */
		ctx = calloc(1, sizeof(uev_ctx_t));
		if (!ctx) {
			ERR(errno, "Failed allocating session event context");
			exit(1);
		}

		uev_init(ctx);
	}
#endif

	err = uftpd_set_nonblock(sd);
	if (err) {
		ERR(errno, "Failed to make session socket non-blocking");
		goto fail;
	}

	ctrl = calloc(1, sizeof(ctrl_t));
	if (!ctrl) {
		ERR(errno, "Failed allocating session context");
		goto fail;
	}

	ctrl->sd = sd;
	ctrl->ctx = ctx;
	strlcpy(ctrl->cwd, "/", sizeof(ctrl->cwd));

#ifndef UFTPD_EMBEDDED
	/* Chroot to FTP root */
	if (!uftpd_chrooted && geteuid() == 0) {
		if (chroot(uftpd_home) || chdir("/")) {
			ERR(errno, "Failed chrooting to FTP root, %s, aborting", uftpd_home);
			goto fail;
		}
		uftpd_chrooted = 1;
	} else if (!uftpd_chrooted) {
		if (chdir(uftpd_home)) {
			WARN(errno, "Failed changing to FTP root, %s, aborting", uftpd_home);
			goto fail;
		}
	}

	/* If ftp user exists and we're running as root we can drop privs */
	if (!privs_dropped && uftpd_pw && geteuid() == 0) {
		int fail1, fail2;

		initgroups(uftpd_pw->pw_name, uftpd_pw->pw_gid);
		if ((fail1 = setegid(uftpd_pw->pw_gid)))
			WARN(errno, "Failed dropping group privileges to gid %d", uftpd_pw->pw_gid);
		if ((fail2 = seteuid(uftpd_pw->pw_uid)))
			WARN(errno, "Failed dropping user privileges to uid %d", uftpd_pw->pw_uid);

		setenv("HOME", uftpd_pw->pw_dir, 1);

		if (!fail1 && !fail2)
			INFO("Successfully dropped privilges to %d:%d (uid:gid)", uftpd_pw->pw_uid, uftpd_pw->pw_gid);

		/* On failure, we tried at least.  Only warn once. */
		privs_dropped = 1;
	}
#endif

	/* Session timeout handler */
	uev_timer_init(ctrl->ctx, &ctrl->timeout_watcher, inactivity_cb, ctrl->ctx, INACTIVITY_TIMER, 0);

	return ctrl;
fail:
	if (ctrl)
		free(ctrl);
#ifndef UFTPD_EMBEDDED
	if (!uftpd_inetd)
		free(ctx);
#endif
	*rc = -1;

	return NULL;
}

int uftpd_del_session(ctrl_t *ctrl, int isftp)
{
	DBG("%sFTP Client session ended.", isftp ? "": "T" );

	if (!ctrl)
		return -1;

	if (isftp && ctrl->sd > 0) {
		shutdown(ctrl->sd, SHUT_RDWR);
		close(ctrl->sd);
	}

	if (ctrl->data_listen_sd > 0) {
		shutdown(ctrl->data_listen_sd, SHUT_RDWR);
		close(ctrl->data_listen_sd);
	}

	if (ctrl->data_sd > 0) {
		shutdown(ctrl->data_sd, SHUT_RDWR);
		close(ctrl->data_sd);
	}

	if (ctrl->buf)
		free(ctrl->buf);

#ifndef UFTPD_EMBEDDED
	if (!uftpd_inetd && ctrl->ctx)
		free(ctrl->ctx);
#endif

	if (ctrl->file)
		free(ctrl->file);

	if (ctrl->fp)
		fclose(ctrl->fp);

	uev_timer_stop(&ctrl->timeout_watcher);
	uev_io_stop(&ctrl->data_watcher);
	uev_io_stop(&ctrl->io_watcher);

	free(ctrl);

	return 0;
}

static void ms_to_timeval(int timeout_ms, struct timeval *tv)
{
    tv->tv_sec = timeout_ms / 1000;
    tv->tv_usec = (timeout_ms - (tv->tv_sec * 1000)) * 1000;
}

int uftpd_poll_write(int fd, int timeout_ms)
{
    fd_set writeset;
    FD_ZERO(&writeset);
    FD_SET(fd, &writeset);
    struct timeval timeout;
    ms_to_timeval(timeout_ms, &timeout);
    return select(fd + 1, NULL, &writeset, NULL, &timeout);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
