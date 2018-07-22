#include <glib.h>
#include <unistd.h>
#include <errno.h>

#include "../provision.h"
#include "../network.h"
#include "../utils.h"
#include "../node.h"

#include "interface.h"

static int out;

void cmd_scan_callback(struct scan_result *res)
{
	char str[37];

	uuid128_to_str(res->device_uuid, str);
	dprintf(out, "%s\n", str);
}

static int cmd_scan_unprovisionned(int argc, char *argv[])
{
	if (argc != 1)
		return -EINVAL;

	if (!strcmp("on", argv[0]))
		provision_scan(cmd_scan_callback, 0);
	else if (!strcmp("off", argv[0]))
		provision_scan_stop();
	else
		return -EINVAL;

	return 0;
}

static int cmd_create_network(int argc, char *argv[])
{
	network_provision_new();
	return 0;
}

static void print_network_info(gpointer data, gpointer user_data)
{
	struct network *net = data;

	dprintf(out, "[%u][nid=0x%02x][addr=0x%04x]\n", net->index, net->nid,
		net->addr);
}

static int cmd_list_network(int argc, char *argv[])
{
	g_slist_foreach(node.network_l, print_network_info, NULL);
	return 0;
}

static int cmd_provision_device(int argc, char *argv[])
{
	uint8_t uuid[16] = {};
	uint16_t addr = 0x0000;

	if (argc < 1)
		return -EINVAL;

	if (str_to_uuid128(argv[0], uuid))
		return -EINVAL;

	if (argc >= 2)
		sscanf(argv[1], "0x%04x", &addr);

	return provision_device(NULL, uuid, 0, addr, NULL);
}

static int cmd_set_uuid(int argc, char *argv[])
{
	uint8_t uuid[16] = {};

	if (argc != 1)
		return -EINVAL;

	if (str_to_uuid128(argv[0], uuid))
		return -EINVAL;

	memcpy(node.uuid, uuid, sizeof(uuid));

	return 0;
}

struct cmd {
	const char *name;
	const char *desc;
	int (*function)(int argc, char *argv[]);
};

static const struct cmd cmdlist[] = {
	{
		.name = "scan",
		.desc = "Scan for unprovisionned nodes",
		.function = cmd_scan_unprovisionned,
	},
	{
		.name = "net-create",
		.desc = "Create new network",
		.function = cmd_create_network,
	},
	{
		.name = "net-list",
		.desc = "List all provisioned networks",
		.function = cmd_list_network,
	},
	{
		.name = "provision",
		.desc = "Provision device",
		.function = cmd_provision_device,
	},
	{
		.name = "set-uuid",
		.desc = "Change device uuid",
		.function = cmd_set_uuid,
	},
};

static void execute(char *cmd)
{
	char *argv[100] = {}, *saveptr;
	int i = 0, argc = 0;

	if (cmd[strlen(cmd) - 1] == '\n')
		cmd[strlen(cmd) - 1] = '\0';

	if (!strlen(cmd))
		return;

	argv[argc++] = strtok_r(cmd, " ", &saveptr);
	while ((argv[argc++] = strtok_r(NULL, " ", &saveptr)));

	for (i = 0; i < ARRAY_SIZE(cmdlist); i++) {
		if (!strcmp(cmdlist[i].name, argv[0])) {
			int ret;

			ret = cmdlist[i].function(argc - 2, &argv[1]);
			if (!ret)
				dprintf(out, "OK\n");
			else
				dprintf(out, "ERROR (%s)\n", strerror(-ret));
			return;
		}
	}

	dprintf(out, "UNKNOWN\n");
}

static gboolean io_callback (GIOChannel *io, GIOCondition cond, gpointer data)
{
	GString *str = g_string_new(NULL);
	GError *error = NULL;

	while (g_io_channel_read_line_string (io, str, NULL, &error)
	       == G_IO_STATUS_NORMAL) {
		execute(str->str);
	}

	g_string_free(str, TRUE);

	return TRUE;
}

void cmdline_deinit(void)
{

}

int cmdline_init(int input, int output)
{
	GIOChannel *io = NULL;
	GError *error = NULL;

	out = output;
	io = g_io_channel_unix_new(input);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, &error);
	g_io_add_watch(io, G_IO_IN, io_callback, NULL);
	g_io_channel_unref(io);

	return 0;
}
