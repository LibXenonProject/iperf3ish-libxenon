#ifndef XENON_IPERF3_H
#define XENON_IPERF3_H

/* iperf3 (3.x protocol) compatible TCP server on top of lwIP raw API. */
#define IPERF3_PORT 5201

void iperf3_server_init(void);

#endif
