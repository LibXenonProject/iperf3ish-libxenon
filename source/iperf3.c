/*
 * Minimal iperf3-protocol server for libxenon (lwIP, NO_SYS, raw API).
 *
 * Upstream iperf3 needs BSD sockets, select() and pthreads, none of which
 * exist in libxenon, so this reimplements the server side of the iperf3
 * control protocol (TCP only, forward and reverse (-R), -P N streams).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <ppc/timebase.h>
#include <time/time.h>

#include "lwip/tcp.h"
#include "lwip/pbuf.h"
#include "lwip/mem.h"

#include "iperf3.h"

/* iperf3 control states */
#define ST_TEST_START       1
#define ST_TEST_RUNNING     2
#define ST_TEST_END         4
#define ST_PARAM_EXCHANGE   9
#define ST_CREATE_STREAMS   10
#define ST_SERVER_TERMINATE 11
#define ST_CLIENT_TERMINATE 12
#define ST_EXCHANGE_RESULTS 13
#define ST_DISPLAY_RESULTS  14
#define ST_IPERF_DONE       16
#define ST_ACCESS_DENIED    ((int8_t)-1)

#define COOKIE_SIZE   37
#define MAX_STREAMS   8
#define CTRL_BUF_SIZE 2048

enum conn_kind { K_NEW, K_CONTROL, K_STREAM };

enum ctrl_phase {
	P_COOKIE,
	P_PARAM_LEN,
	P_PARAMS,
	P_WAIT_STREAMS,
	P_RUNNING,
	P_RES_LEN,
	P_RES,
	P_WAIT_DONE,
};

struct conn {
	enum conn_kind kind;
	struct tcp_pcb *pcb;
	int cookie_got;
	char cookie[COOKIE_SIZE];
	int stream_idx;
};

struct stream {
	struct conn *c;
	uint64_t bytes;
};

static struct session {
	int active;
	char cookie[COOKIE_SIZE];
	struct conn *ctrl;
	enum ctrl_phase phase;
	uint8_t buf[CTRL_BUF_SIZE];
	int buf_len;
	uint32_t need;           /* bytes needed for current phase */
	int reverse;
	int parallel;
	int blksize;
	int nstreams;
	struct stream streams[MAX_STREAMS];
	uint64_t t_start;
	uint64_t t_end;
} S;

static struct tcp_pcb *listen_pcb;

/* payload for reverse mode; static so tcp_write can reference it (no copy) */
#define TX_BLOCK 1460
static uint8_t tx_block[TX_BLOCK];

static void session_reset(void);
static void conn_close(struct conn *c);

static void ctrl_send_state(int8_t st)
{
	if (!S.ctrl || !S.ctrl->pcb) return;
	tcp_write(S.ctrl->pcb, &st, 1, TCP_WRITE_FLAG_COPY);
	tcp_output(S.ctrl->pcb);
}

static uint32_t read_be32(const uint8_t *p)
{
	return (uint32_t)p[0] << 24 | (uint32_t)p[1] << 16 |
	       (uint32_t)p[2] << 8 | p[3];
}

static void ctrl_send_json(const char *json)
{
	uint32_t n = strlen(json);
	uint8_t be[4] = { n >> 24, n >> 16, n >> 8, n };
	tcp_write(S.ctrl->pcb, be, sizeof(be), TCP_WRITE_FLAG_COPY);
	tcp_write(S.ctrl->pcb, json, n, TCP_WRITE_FLAG_COPY);
	tcp_output(S.ctrl->pcb);
}

static const char *json_find(const char *json, const char *key)
{
	char pat[40];
	snprintf(pat, sizeof(pat), "\"%s\"", key);
	const char *p = strstr(json, pat);
	if (!p) return NULL;
	p += strlen(pat);
	while (*p == ' ' || *p == ':') p++;
	return p;
}

static int json_bool(const char *json, const char *key)
{
	const char *p = json_find(json, key);
	return p && !strncmp(p, "true", 4);
}

static int json_int(const char *json, const char *key, int def)
{
	const char *p = json_find(json, key);
	return p ? atoi(p) : def;
}

static uint64_t now_ms(void)
{
	return tb_diff_msec(mftb(), 0);
}

static void stream_pump(struct stream *s)
{
	struct tcp_pcb *pcb = s->c ? s->c->pcb : NULL;
	if (!pcb || !S.reverse || S.phase != P_RUNNING) return;

	while (tcp_sndbuf(pcb) >= TX_BLOCK) {
		if (tcp_write(pcb, tx_block, TX_BLOCK, 0) != ERR_OK)
			break;
		s->bytes += TX_BLOCK;
	}
	tcp_output(pcb);
}

static void pump_all(void)
{
	for (int i = 0; i < S.nstreams; i++)
		stream_pump(&S.streams[i]);
}

static err_t stream_sent(void *arg, struct tcp_pcb *pcb, u16_t len)
{
	struct conn *c = arg;
	(void)pcb; (void)len;
	if (c->kind == K_STREAM && S.active)
		stream_pump(&S.streams[c->stream_idx]);
	return ERR_OK;
}

static err_t stream_poll(void *arg, struct tcp_pcb *pcb)
{
	struct conn *c = arg;
	(void)pcb;
	if (c->kind == K_STREAM && S.active)
		stream_pump(&S.streams[c->stream_idx]);
	return ERR_OK;
}

static void start_test(void)
{
	ctrl_send_state(ST_TEST_START);
	ctrl_send_state(ST_TEST_RUNNING);
	S.phase = P_RUNNING;
	S.need = 1;
	S.t_start = now_ms();
	printf("iperf3: test started (%s, %d stream(s))\n",
	       S.reverse ? "reverse" : "forward", S.nstreams);
	pump_all();
}

static void print_summary(void)
{
	uint64_t ms = S.t_end - S.t_start;
	if (!ms) ms = 1;
	for (int i = 0; i < S.nstreams; i++) {
		uint64_t kbit = S.streams[i].bytes * 8 / ms; /* bits/ms == kbit/s */
		printf("iperf3: stream %d: %u bytes in %u ms = %u.%03u Mbit/s\n", i,
		       (unsigned)S.streams[i].bytes, (unsigned)ms,
		       (unsigned)(kbit / 1000), (unsigned)(kbit % 1000));
	}
}

static void send_results(void)
{
	char json[1024];
	int n = snprintf(json, sizeof(json),
		"{\"cpu_util_total\":0,\"cpu_util_user\":0,\"cpu_util_system\":0,"
		"\"sender_has_retransmits\":0,\"streams\":[");
	for (int i = 0; i < S.nstreams; i++) {
		n += snprintf(json + n, sizeof(json) - n,
			"%s{\"id\":%d,\"bytes\":%llu,\"retransmits\":-1,\"jitter\":0,"
			"\"errors\":0,\"packets\":0,\"start_time\":0,\"end_time\":%u.%03u}",
			i ? "," : "", i ? i + 2 : 1,
			(unsigned long long)S.streams[i].bytes,
			(unsigned)((S.t_end - S.t_start) / 1000),
			(unsigned)((S.t_end - S.t_start) % 1000));
	}
	snprintf(json + n, sizeof(json) - n, "]}");
	ctrl_send_json(json);
}

/* consume as many complete control phases as are buffered */
static void ctrl_process(void)
{
	while ((uint32_t)S.buf_len >= S.need && S.need) {
		uint32_t used = S.need;

		switch (S.phase) {
		case P_PARAM_LEN: {
			uint32_t len = read_be32(S.buf);
			if (len == 0 || len >= CTRL_BUF_SIZE) { conn_close(S.ctrl); return; }
			S.phase = P_PARAMS;
			S.need = len;
			break;
		}
		case P_PARAMS: {
			S.buf[used] = 0;
			const char *j = (const char *)S.buf;
			S.reverse  = json_bool(j, "reverse");
			S.parallel = json_int(j, "parallel", 1);
			S.blksize  = json_int(j, "len", 131072);
			if (!json_bool(j, "tcp") && json_find(j, "udp")) {
				printf("iperf3: UDP not supported\n");
				ctrl_send_state(ST_ACCESS_DENIED);
				conn_close(S.ctrl);
				return;
			}
			if (S.parallel < 1) S.parallel = 1;
			if (S.parallel > MAX_STREAMS) S.parallel = MAX_STREAMS;
			S.nstreams = 0;
			S.phase = P_WAIT_STREAMS;
			S.need = 0; /* streams arrive on other connections */
			ctrl_send_state(ST_CREATE_STREAMS);
			break;
		}
		case P_RUNNING: {
			int8_t st = (int8_t)S.buf[0];
			if (st == ST_TEST_END) {
				S.t_end = now_ms();
				print_summary();
				ctrl_send_state(ST_EXCHANGE_RESULTS);
				S.phase = P_RES_LEN;
				S.need = 4;
			} else if (st == ST_CLIENT_TERMINATE) {
				conn_close(S.ctrl);
				return;
			}
			break;
		}
		case P_RES_LEN: {
			uint32_t len = read_be32(S.buf);
			if (len == 0 || len >= CTRL_BUF_SIZE) { conn_close(S.ctrl); return; }
			S.phase = P_RES;
			S.need = len;
			break;
		}
		case P_RES:
			/* client results are ignored; answer with ours */
			send_results();
			ctrl_send_state(ST_DISPLAY_RESULTS);
			S.phase = P_WAIT_DONE;
			S.need = 1;
			break;
		case P_WAIT_DONE:
			printf("iperf3: test done\n");
			conn_close(S.ctrl);
			return;
		default:
			return;
		}

		S.buf_len -= used;
		memmove(S.buf, S.buf + used, S.buf_len);
	}
}

static void session_reset(void)
{
	for (int i = 0; i < S.nstreams; i++) {
		struct conn *c = S.streams[i].c;
		S.streams[i].c = NULL;
		if (c && c->pcb) conn_close(c);
	}
	memset(&S, 0, sizeof(S));
}

static void conn_close(struct conn *c)
{
	struct tcp_pcb *pcb = c->pcb;
	enum conn_kind kind = c->kind;

	if (pcb) {
		c->pcb = NULL;
		tcp_arg(pcb, NULL);
		tcp_recv(pcb, NULL);
		tcp_sent(pcb, NULL);
		tcp_poll(pcb, NULL, 0);
		tcp_err(pcb, NULL);
		if (tcp_close(pcb) != ERR_OK)
			tcp_abort(pcb);
	}

	if (kind == K_CONTROL && S.active && S.ctrl == c) {
		S.ctrl = NULL;
		session_reset();
	} else if (kind == K_STREAM && S.active) {
		S.streams[c->stream_idx].c = NULL;
	}
	mem_free(c);
}

static void conn_err(void *arg, err_t err)
{
	struct conn *c = arg; /* pcb is already freed by lwIP */
	(void)err;
	if (c) { c->pcb = NULL; conn_close(c); }
}

static void conn_adopt(struct conn *c)
{
	char cookie[COOKIE_SIZE];
	memcpy(cookie, c->cookie, COOKIE_SIZE);

	if (!S.active) {
		memset(&S, 0, sizeof(S));
		S.active = 1;
		memcpy(S.cookie, cookie, COOKIE_SIZE);
		S.ctrl = c;
		c->kind = K_CONTROL;
		S.phase = P_PARAM_LEN;
		S.need = 4;
		ctrl_send_state(ST_PARAM_EXCHANGE);
		printf("iperf3: client connected\n");
	} else if (!memcmp(S.cookie, cookie, COOKIE_SIZE) &&
	           S.phase == P_WAIT_STREAMS && S.nstreams < S.parallel) {
		c->kind = K_STREAM;
		c->stream_idx = S.nstreams;
		S.streams[S.nstreams].c = c;
		S.streams[S.nstreams].bytes = 0;
		S.nstreams++;
		if (S.nstreams == S.parallel)
			start_test();
	} else {
		int8_t st = ST_ACCESS_DENIED;
		tcp_write(c->pcb, &st, 1, TCP_WRITE_FLAG_COPY);
		tcp_output(c->pcb);
		conn_close(c);
	}
}

static err_t conn_recv(void *arg, struct tcp_pcb *pcb, struct pbuf *p, err_t err)
{
	struct conn *c = arg;
	(void)err;

	if (!p) { /* remote closed */
		if (c) conn_close(c);
		return ERR_OK;
	}

	for (struct pbuf *q = p; q; q = q->next) {
		const uint8_t *d = q->payload;
		int len = q->len;

		if (c->kind == K_NEW) {
			int take = COOKIE_SIZE - c->cookie_got;
			if (take > len) take = len;
			memcpy(c->cookie + c->cookie_got, d, take);
			c->cookie_got += take;
			d += take;
			len -= take;
			if (c->cookie_got == COOKIE_SIZE) {
				conn_adopt(c);
				if (!c->pcb) { pbuf_free(p); return ERR_ABRT; }
			}
		}

		if (len > 0) {
			if (c->kind == K_CONTROL) {
				if (S.buf_len + len > CTRL_BUF_SIZE) len = CTRL_BUF_SIZE - S.buf_len;
				memcpy(S.buf + S.buf_len, d, len);
				S.buf_len += len;
				ctrl_process();
				if (!c->pcb) { pbuf_free(p); return ERR_ABRT; }
			} else if (c->kind == K_STREAM && !S.reverse) {
				S.streams[c->stream_idx].bytes += len;
			}
		}
	}

	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	return ERR_OK;
}

static err_t conn_accept(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	(void)arg; (void)err;
	struct conn *c = mem_malloc(sizeof(*c));
	if (!c) return ERR_MEM;
	memset(c, 0, sizeof(*c));
	c->kind = K_NEW;
	c->pcb = newpcb;

	tcp_arg(newpcb, c);
	tcp_recv(newpcb, conn_recv);
	tcp_sent(newpcb, stream_sent);
	tcp_poll(newpcb, stream_poll, 1);
	tcp_err(newpcb, conn_err);
	tcp_nagle_disable(newpcb);
	return ERR_OK;
}

void iperf3_server_init(void)
{
	for (int i = 0; i < TX_BLOCK; i++)
		tx_block[i] = i % 10 + '0';

	struct tcp_pcb *pcb = tcp_new();
	tcp_bind(pcb, IP_ADDR_ANY, IPERF3_PORT);
	listen_pcb = tcp_listen(pcb);
	tcp_accept(listen_pcb, conn_accept);
	printf("iperf3: listening on port %d\n", IPERF3_PORT);
}
