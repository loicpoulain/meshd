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

#ifndef __ACCESS_H
#define __ACCESS_H

#include <stdint.h>
#include <glib.h>

/**
 * struct param_desc - access message parameter description
 * @name:	paramater name
 * @type:	parameter type
 */
struct param_desc {
	const char *name;
	int type;
};
#define PARAM_BYTE ((int) 'y')
#define PARAM_INT16 ((int) 'n')
#define PARAM_UINT16 ((int) 'q')
#define PARAM_INT32 ((int) 'i')
#define PARAM_UINT32 ((int) 'u')

struct amsg_desc;

typedef int (*amsg_onrecv_cb)(const struct amsg_desc *desc, uint8_t *params);
typedef int (*amsg_onsend_cb)(const struct amsg_desc *desc, uint8_t *params);

/**
 * struct amsg_desc - access message parameter description
 * @desc:	human readable name
 * @opcode:	access msg opcode
 * @response:	expected response in case of acknowledged msg (optional)
 * @params:	list of parameter description if any (optional)
 * @onrecv:	callback on access msg reception
 */
struct amsg_desc {
	const char *desc;
	uint32_t opcode;
	const struct amsg_desc *response;
	const struct param_desc *params;
	amsg_onrecv_cb onrecv;
	amsg_onsend_cb onsend;
};

/**
 * struct state - mesh state exposed from element (server)
 * desc:	human readable state name
 * @rx:		array of supported rx access msgs
 * @tx:		array of supported tx access msgs
 */
struct state {
	const char *desc;
	const struct amsg_desc **rx;
	const struct amsg_desc **tx;
};

/**
 * struct server_model - mesh server model
 * id:		Mesh Model ID (SIG or Vendor)
 * desc:	human readable model name
 * states:	exposed states
 */
struct server_model {
	uint32_t id;
	const char *desc;
	const struct state **states;
};

/**
 * struct client_model - mesh client model
 * id:          Mesh Model ID (SIG or Vendor)
 * desc:        human readable model name
 */
struct client_model {
	uint32_t id;
	const char *desc;
};

/**
 * struct element - element
 * index:	element index (0 is the primary element)
 * subscribe_l:	list of subscribed addr
 * serv_model_l: registered models
 */
struct element {
	uint8_t index;
	GSList *subscribe_l;
	GSList *serv_model_l;
};

struct element *element_by_index(int index);
struct element *element_by_address(uint16_t addr);
int access_recv_msg(void *data, size_t len, uint16_t src,
		    uint16_t dst);
struct element *element_create(int index);
int register_server_model(struct server_model *model, int instance);

#endif
