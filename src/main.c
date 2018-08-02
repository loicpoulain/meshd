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

static const struct option main_options[] = {
	{ "help", no_argument, NULL, 'h' },
	{ "interactive", no_argument, NULL, 'i' },
	{ }
};

int main(int argc, char *argv[])
{
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

	g_main_loop_unref(mainloop);

	return 0;
}
