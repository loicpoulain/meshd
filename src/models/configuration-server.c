#include "../access.h"

/* Secure Network Beacon */
static const struct amsg_desc config_beacon_status = {
	.desc = "config-beacon-status",
	.opcode = 0x800B,
	.params = (const struct param_desc[]) { { "beacon", PARAM_BYTE }, { } },
};

static const struct amsg_desc config_beacon_get = {
	.desc = "config-beacon-get",
	.opcode = 0x8009,
	.response = &config_beacon_status,
};

static const struct amsg_desc config_beacon_set = {
	.desc = "config-beacon-set",
	.opcode = 0x800A,
	.response = &config_beacon_status,
	.params = (const struct param_desc[]) { { "beacon", PARAM_BYTE }, { } },
};

static struct state secure_network_beacon_state = {
	.desc = "secure-network-beacon",
	.rx = (const struct amsg_desc*[]) { &config_beacon_get,
					    &config_beacon_set, NULL },
	.tx = (const struct amsg_desc*[]) { &config_beacon_status, NULL },
};

/* Default TTL */
static const struct amsg_desc config_ttl_status = {
	.desc = "config-ttl-status",
	.opcode = 0x800E,
	.params = (const struct param_desc[]) { { "ttl", PARAM_BYTE }, { } },
};

static const struct amsg_desc config_ttl_get = {
	.desc = "config-ttl-get",
	.opcode = 0x800C,
	.response = &config_ttl_status,
};

static const struct amsg_desc config_ttl_set = {
	.desc = "config-ttl-set",
	.opcode = 0x800D,
	.response = &config_ttl_status,
	.params = (const struct param_desc[]) { { "ttl", PARAM_BYTE }, { } },
};

static const struct state default_ttl_state = {
	.desc = "secure-network-beacon",
	.rx = (const struct amsg_desc*[]) { &config_beacon_get,
					    &config_beacon_set, NULL },
	.tx = (const struct amsg_desc*[]) { &config_beacon_status, NULL },
};

static struct model configuration_server_model = {
	.id = 0x0000,
	.desc = "Configuation server",
	.states = (const struct state*[]) { &secure_network_beacon_state,
					    &default_ttl_state, NULL },
};

int configuration_server_model_init(void)
{
	return register_model(&configuration_server_model, 0);
}
