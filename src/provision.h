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

#ifndef __PROVISION_H
#define __PROVISION_H

#include <stdbool.h>

#include "utils.h"

/* ---------------- PROV PROTOCOL -------------------- */

/**
 * struct prov_interface - Provisioning Interface
 * @open:	Open new provisioning Session (Establish transport layer)
 * @close:	Close a provisionin Session
 * @send:	Send provisioning pdu to provisioning transport layer
 * @scan:	(optional) Scan mesh beacon
 * @beacon:	(optional) Send mesh beacon
 */
struct prov_interface {
	int (*open)(struct prov_interface *, void *, uint8_t device_uuid[16]);
	void (*close)(struct prov_interface *, void *, int);
	int (*send)(struct prov_interface *, void *, void *, size_t);
	int (*scan)(struct prov_interface *, bool enable);
	int (*beacon)(struct prov_interface *, void *, size_t);
};

struct scan_result {
	uint8_t device_uuid[16];
	struct prov_interface *pif;
};

/* This is a very basic address mgmt */
/* TODO: bette db with addr releasing, etc ... */
static struct provision_db {
	uint16_t min_addr;
	uint16_t max_addr;
	uint16_t last_assigned
};

int prov_register_interface(struct prov_interface *pif);
int prov_unregister_interface(struct prov_interface *pif);
int provision_recv_pkt(void *session_id, void *pkt, size_t plen);
void provision_recv_beacon(struct prov_interface *pif, const void *beacon,
			   size_t size);
void *provision_accept(struct prov_interface *pif);

typedef void (*prov_scan_callack_t)(struct scan_result *res);
typedef void (*prov_dev_callack_t)(int result);

int provision_scan(prov_scan_callack_t callback, int duration);
int provision_device(struct prov_interface *pif,
		     uint8_t device_uuid[16],
		     int net_index, uint16_t addr,
		     prov_dev_callack_t cb);


/* ------------------ GENERIC PROV -------------------- */
/**
 * struct generic_prov_bearer - Generic Provisioning Bearer
 * @name:	provisioning bearer name
 * @mtu:	MTU, maximum fragment size
 * @send:	Send generic provisioning pdu to bearer
 * @scan:	(optional) start/stop unprovisioned device scanning
 * @priv:	provision generic priv data
 */
struct generic_prov_bearer {
	char name[11];
	size_t mtu;
	int (*send)(struct generic_prov_bearer *gpb, int link_id, int trans_id,
		    void *data, size_t len);
	int (*scan)(struct generic_prov_bearer *gpb, bool enable);
	int (*beacon)(struct generic_prov_bearer *gpb, void *beacon,
		      size_t size);
	void *priv;
};

int generic_prov_bearer_register(struct generic_prov_bearer *gpbearer);
void generic_prov_bearer_unregister(struct generic_prov_bearer *gpbearer);
int generic_prov_recv(struct generic_prov_bearer *gpb, int link_id,
		      int trans_id, void *data, size_t dlen);
void generic_prov_recv_beacon(struct generic_prov_bearer *gpb,
			      const void *beacon, size_t size);


#endif
