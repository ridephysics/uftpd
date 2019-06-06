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

#include "uftpd.h"

char *uftpd_prognm = "uftpd";
int uftpd_do_syslog = 0;

/* Event contexts */
static uev_t ftp_watcher;

static void session_thread_fn(void *_client) {
	int client = (int)_client;
	uev_ctx_t ctx;

	uev_init(&ctx);
	uftpd_ftp_session(&ctx, client);
	vTaskDelete(NULL);
}

static void ftp_cb(uev_t *w, void *arg, int events)
{
	BaseType_t xrc;
	int client;
	TaskHandle_t task;

	if (UEV_ERROR == events) {
		uev_io_stop(w);
		close(w->fd);
		return;
	}

	client = accept(w->fd, NULL, NULL);
	if (client < 0) {
		WARN(errno, "Failed accepting FTP client connection");
		return;
	}

	xrc = xTaskCreate(session_thread_fn, "uftpd_session", 8192, (void*)client, ESP_TASK_MAIN_PRIO, &task);
	if (xrc != pdTRUE) {
		ERR(0, "can't create client thread");
		shutdown(client, SHUT_RDWR);
		close(client);
		return;
	}
}

static int start_service(uev_ctx_t *ctx, uev_t *w, uev_cb_t *cb, int port, int type, char *desc)
{
	int sd;

	if (!port)
		/* Disabled */
		return 1;

	sd = uftpd_open_socket(port, type, desc);
	if (sd < 0) {
		if (EACCES == errno)
			WARN(0, "Not allowed to start %s service.%s",
				 desc, port < 1024 ? "  Privileged port." : "");
		return 1;
	}

	INFO("Starting %s server on port %d ...", desc, port);
	uev_io_init(ctx, w, cb, ctx, sd, UEV_READ);

	return 0;
}

static int serve_files(uev_ctx_t *ctx)
{
	int rc;

	DBG("Starting services ...");
	rc  = start_service(ctx, &ftp_watcher,   ftp_cb, FTP_DEFAULT_PORT, SOCK_STREAM, "FTP");
	if (rc)
		return -1;

	return 0;
}

int uftpd_start(uev_ctx_t *ctx)
{
	uftpd_loglevel = LOG_DEBUG;
	return serve_files(ctx);
}

/**
 * Local Variables:
 *  indent-tabs-mode: t
 *  c-file-style: "linux"
 * End:
 */
