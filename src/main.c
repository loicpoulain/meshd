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

#include "node.h"
#include "utils.h"
#include "workqueue.h"
#include "network.h"
#include "provision.h"
#include "transport.h"

GMainLoop *mainloop;
struct node_st node;

gboolean signal_handler_interrupt(gpointer data)
{
	g_main_loop_quit(mainloop);

	g_message("exiting meshd");

	return G_SOURCE_CONTINUE;
}

static void prov_cb(int result)
{
	char data[] = "hello world how are you doing world this is a long msg";

	transport_up_send_access_msg(node.network_l->data, data, sizeof(data) - 4, 0x4242, 0x1234, 0);
	//transport_up_send_access_msg(node.network_l->data, data, sizeof(data) - 4, 0x4242, 0x1235, 0);
}

int main(int argc, char *argv[])
{
	guint sid;

	mainloop = g_main_loop_new(NULL, FALSE);
	if (mainloop == NULL)
		return -ENOMEM;

	/* crypto */
	crypto_init();

	/* init client interface */
	/* init radios */

	/* Signal handlers */
	//sid = g_unix_signal_add(SIGINT, signal_handler_interrupt, mainloop);

	hci_channel_init();
	network_layer_init();
	provision_init();

	{
		//char data[] = "hello world how are you doing world this is a long msg";
		//char data1[] = "hello world how are you doing world this is a long msg";
		//char data2[] = "hello world how are you doing world this is a long msg";
		//struct network *net = network_provision_new();
		//transport_up_send_access_msg(net, data, sizeof(data) - 4, 0x4242, 0x4343, 0);
		//transport_up_send_access_msg(net, data1, sizeof(data1) - 4, 0x4242, 0xFFFF, 0);
		//transport_up_send_access_msg(net, data2, sizeof(data2) - 4, 0x4242, 0xC001, 0);
	}

	{
		element_create(0);
		struct network *net = network_provision_new();
		uint8_t uuid[16] = { };
		provision_device(NULL, uuid, 0, 0x1234, prov_cb);
		//prov_cb(0);
	}

	g_main_loop_run(mainloop);

	crypto_cleanup();

	//g_source_remove(sid);

	g_main_loop_unref(mainloop);

	return 0;
}
