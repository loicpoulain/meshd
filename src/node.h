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

#ifndef __NODE_H
#define __NODE_H

#include <glib.h>

#include "crypto.h"

struct node_st {
	GSList *network_l;
	GSList *element_l;
	enum {  STATE_UNPROVISIONED,
		STATE_PROVISIONING,
		STATE_PROVISIONED } state;
	uint8_t uuid[16];
	uint16_t cid;
       	uint16_t pid;
	uint16_t vid;
       	uint16_t crpl;
};

extern struct node_st node;

#endif
