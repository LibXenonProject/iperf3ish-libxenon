#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <debug.h>
#include <xenos/xenos.h>
#include <console/console.h>
#include <network/network.h>

#include "iperf3.h"

int main(){
  xenos_init(VIDEO_MODE_AUTO);
  console_init();

  printf("libxenon iperf3 server\n");
  int r = network_init();
  printf("network_init -> %d\n", r);
  network_print_config();

  iperf3_server_init();

  for (;;)
    network_poll();

  return 0;
}
