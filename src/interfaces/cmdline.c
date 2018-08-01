#include <glib.h>
#include <unistd.h>
#include <errno.h>

#include "../provision.h"
#include "../network.h"
#include "../utils.h"
#include "../node.h"

#include "interface.h"

static int out;

/* DIRTY CMDLINE INTERFACE */

struct cmd {
	const char *name;
	const char *desc;
	int (*function)(int argc, char *argv[]);
};

void cmd_scan_callback(struct scan_result *res)
{
	char str[37];

	uuid128_to_str(res->device_uuid, str);
	dprintf(out, "\r[unprov] %s\n> ", str);
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

	dprintf(out, "\r[net][index=%u][nid=0x%02x][addr=0x%04x]\n> ",
		net->index, net->nid, net->addr);
}

static int cmd_list_network(int argc, char *argv[])
{
	g_slist_foreach(node.network_l, print_network_info, NULL);
	return 0;
}

static int cmd_provision_device(int argc, char *argv[])
{
	uint8_t uuid[16] = {};
	unsigned int addr = 0x0000;
	struct network *net;

	if (argc < 1)
		return -EINVAL;

	if (str_to_uuid128(argv[0], uuid))
		return -EINVAL;

	if (argc >= 2) {
		unsigned int nid;

		sscanf(argv[1], "0x%02x", &nid);
		net = network_by_nid(nid);
		if (!net)
			return -ENONET;
	}

	if (argc >= 3)
		sscanf(argv[2], "0x%04x", &addr);

	return provision_device(NULL, uuid, net ? net->index : 0, addr, NULL);
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

static int cmd_get_uuid(int argc, char *argv[])
{
	char uuid[37];

	uuid128_to_str(node.uuid, uuid);

	dprintf(out, "\r%s\n> ", uuid);

	return 0;
}

static int cmd_sendnet(int argc, char *argv[])
{
	struct network_msg *nmsg;
	struct network *net;
	unsigned int value;
	uint16_t addr;
	uint8_t nid;
	uint32_t seq;
	int ret, i = 0;

	if (argc != 3)
		return -EINVAL;

	sscanf(argv[0], "%x", &value);
	nid = value;
	sscanf(argv[1], "%x", &value);
	addr = value;

	net = network_by_nid(nid);
	if (!net)
		return -ENONET;

	nmsg = network_msg_alloc(NMSG_HDR_SZ(NULL));
	if (!nmsg)
		return -ENOMEM;

	nmsg->src = cpu_to_be16(net->addr);
	nmsg->dst = cpu_to_be16(addr);

	/* TODO make seq configurable */
	seq = network_peek_seq(net);
	nmsg->seq[0] = seq >> 16;
	nmsg->seq[1] = seq >> 8;
	nmsg->seq[2] = seq;

	/* TODO make ctrl configurable */
	nmsg->ctl = 0x00;
	nmsg->len += 4; /* non ctrl msg mic */

	while (sscanf(argv[2], "%hhx %s", &nmsg->pdu_mic[i++], argv[2]) == 2);
	nmsg->len += i;

	ret = network_send_msg(net, nmsg);
	network_msg_unref(nmsg);

	return ret;
}

static int cmd_help(int argc, char *argv[]);
static const struct cmd cmdlist[] = {
	{
		.name = "scan",
		.desc = "<on|off>\tScan for unprovisionned nodes",
		.function = cmd_scan_unprovisionned,
	},
	{
		.name = "net-create",
		.desc = "\tCreate new network",
		.function = cmd_create_network,
	},
	{
		.name = "net-prov",
		.desc = "<uuid> <nid> <address>\tProvision device",
		.function = cmd_provision_device,
	},
	{
		.name = "net-list",
		.desc = "\tList all provisioned networks",
		.function = cmd_list_network,
	},
	{
		.name = "net-send",
		.desc = "<NID> <addr> <data> Send raw network message",
		.function = cmd_sendnet,
	},
	{
		.name = "set-uuid",
		.desc = "<uuid>\tSet local node uuid",
		.function = cmd_set_uuid,
	},
	{
		.name = "get-uuid",
		.desc = "\t Get local node uuid",
		.function = cmd_get_uuid,
	},
	{
		.name = "help",
		.desc = "\thelp menu",
		.function = cmd_help,
	},
};

static int cmd_help(int argc, char *argv[])
{
	int i = 0;

	for (i = 0; i < ARRAY_SIZE(cmdlist); i++) {
		dprintf(out, "\r[help] %s %s\n> ", cmdlist[i].name,
			cmdlist[i].desc);
	}

	return 0;
}

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
				dprintf(out, "\rOK\n> ");
			else
				dprintf(out, "\rERROR (%s)\n> ",
					strerror(-ret));
			return;
		}
	}

	dprintf(out, "\rUNKNOWN\n> ");
}

static gboolean io_callback (GIOChannel *io, GIOCondition cond, gpointer data)
{
	GString *str = g_string_new(NULL);
	GError *error = NULL;

	while (g_io_channel_read_line_string (io, str, NULL, &error)
	       == G_IO_STATUS_NORMAL) {
		execute(str->str);
	}

	dprintf(out, "\r> ");

	g_string_free(str, TRUE);

	return TRUE;
}

void cmdline_deinit(void)
{

}

static void cmdline_network_recv(struct network *net, struct network_msg *nmsg)
{
	char data[128] = { };
	int i;

	uint16_t src = be16_to_cpu(nmsg->src);
	uint16_t dst = be16_to_cpu(nmsg->dst);

	for (i = 0; i < NMSG_PDU_SZ(nmsg); i++) {
		sprintf(data, "%s%02x", data, nmsg->pdu_mic[i]);
	}

	dprintf(out,
		"\r[net-recv][nid=0x%02x][src=0x%04x][dst=0x%04x][data=%s]\n> ",
		net->nid, src, dst, data);

}

static void cmdline_network_add(struct network *net)
{
	dprintf(out, "\r[net-add][index=%u][nid=0x%02x]\n> ", net->index,
		net->nid);
}

struct user_interface cmdline_intf = {
	.name = "cmdline",
	.network_recv = cmdline_network_recv,
	.network_add = cmdline_network_add,
};

int cmdline_init(int input, int output)
{
	GIOChannel *io = NULL;
	GError *error = NULL;

	out = output;
	io = g_io_channel_unix_new(input);
	g_io_channel_set_flags(io, G_IO_FLAG_NONBLOCK, &error);
	g_io_add_watch(io, G_IO_IN, io_callback, NULL);
	g_io_channel_unref(io);

	register_user_intf(&cmdline_intf);

	return 0;
}
