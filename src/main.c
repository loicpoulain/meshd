/*
 *
 * Meshd, Bluetooth mesh stack
 *
 * Copyright (C) 2017  Loic Poulain <loic.poulain@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#include <glib.h>
#include <errno.h>
#include <stdbool.h>
#include <getopt.h>
#include <unistd.h>

#include "node.h"
#include "utils.h"
#include "workqueue.h"
#include "network.h"
#include "provision.h"
#include "transport.h"
#include "bearer.h"
#include "access.h"

#include "interfaces/interface.h"

GMainLoop *mainloop;
struct node_st node;

gboolean signal_handler_interrupt(gpointer data)
{
	g_main_loop_quit(mainloop);

	g_message("exiting meshd");

	return G_SOURCE_CONTINUE;
}


static void tmp_provion_cb(int result)
{
	if (result)
		g_message("prov error");

	g_message("prov success");
}

/* SIGUSR1 provision device UUID 00000000 with address 0x1234 .... */
static struct network *net;
gboolean tmp_prov(gpointer d)
{
	/* tmp self provision network */
	if (!net)
		net = network_provision_new();

	/* provision peer device */
	uint8_t uuid[16] = { };
	provision_device(NULL, uuid, 0, 0x1234, tmp_provion_cb);

	return true;
}

/* SIGUSR2 Send msg to 0x1234 */
gboolean tmp_sendmsg(gpointer d)
{
	char data[] = "hello world this is a long message...";
	struct network *net = g_list_first(node.network_l)->data;

	if (!net)
		g_message("No network");

	g_message("send msg network %p nid=%x", net, net->nid);
	transport_up_send_access_msg(net,
				     data, sizeof(data) - 4, net->addr, 0x1234, 0);

	return true;
}

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "interactive", no_argument, NULL, 'i' },
	{ }
};

int main(int argc, char *argv[])
{
	guint sid0, sid1, sid2, sid3;
	bool interactive;

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL)
		return -ENOMEM;

	for (;;) {
		int opt = getopt_long(argc, argv, "hi", main_options, NULL);
		if (opt < 0)
			break;
			switch (opt) {
		case 'i':
			interactive = true;
			break;
		}
	}

	/* Signal handlers */
	//sid0 = g_unix_signal_add(SIGINT, signal_handler_interrupt, mainloop);
	/* tmp for dbg purpose */
	sid1 = g_unix_signal_add(SIGUSR1, tmp_prov, mainloop);
	sid2 = g_unix_signal_add(SIGUSR2, tmp_sendmsg, mainloop);
	element_create(0);

	crypto_init();
	network_init();
	provision_init();
	bearer_adv_init();
	configuration_server_model_init();

	if (interactive)
		cmdline_init(STDIN_FILENO, STDOUT_FILENO);

	g_main_loop_run(mainloop);

	crypto_cleanup();
	network_cleanup();

	g_source_remove(sid0);
	g_source_remove(sid1);
	g_source_remove(sid2);
	g_source_remove(sid3);

	g_main_loop_unref(mainloop);

	return 0;
}
