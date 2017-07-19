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

#include <stdio.h>

#include "network.h"
#include "provision.h"

#include "advertisers/advertiser.h"

#define AD_TYPE_MESH_MSG	0x42 /* TODO: TBD */
#define AD_TYPE_MESH_PROV	0x43 /* TODO: TBD */
#define AD_TYPE_MESH_BEACON	0x44 /* TODO: TBD */

static int idx;

struct bearer_adv_data {
	struct network_intf nif;
	struct generic_prov_bearer gpb;
	struct advertiser *adv;
};

struct ad_struct {
	uint8_t len;
	uint8_t type;
	uint8_t data[29];
} __attribute__((__packed__));

struct pb_adv_pdu {
	uint32_t link_id;
	uint8_t trans_num;
	uint8_t gen_prov_pdu[0];
} __attribute__((__packed__));

#define nif2badv(nifp) container_of(nifp, struct bearer_adv_data, nif)
#define gpb2badv(gpbp) container_of(gpbp, struct bearer_adv_data, gpb)

static int bearer_adv_prov_send(struct generic_prov_bearer *gpb, int link_id,
				int trans_id, void *data, size_t len)
{
	struct bearer_adv_data *badv = gpb2badv(gpb);
	struct pb_adv_pdu *pbadv;
	struct ad_struct ad;

	ad.len = sizeof(ad.type) + sizeof(*pbadv) + len;
	ad.type = AD_TYPE_MESH_PROV;

	pbadv = (struct pb_adv_pdu *)ad.data;
	pbadv->link_id = cpu_to_be32(link_id);
	pbadv->trans_num = trans_id;
	memcpy(pbadv->gen_prov_pdu, data, len);

	badv->adv->add(badv->adv, &ad, ad.len + sizeof(ad.len), 0);

	return 0;
}

static int bearer_adv_prov_beacon(struct generic_prov_bearer *gpb, void *beacon,
				  size_t len)
{
	struct bearer_adv_data *badv = gpb2badv(gpb);
	struct ad_struct ad;

	ad.len = sizeof(ad.type) + len;
	ad.type = AD_TYPE_MESH_BEACON;
	memcpy(ad.data, beacon, len);

	badv->adv->add(badv->adv, &ad, sizeof(ad.len) + ad.len, 0);

	return 0;
}

static void bearer_adv_recv_msg(struct bearer_adv_data *badv,
				const struct ad_struct *ad)
{
	struct network_msg *msg = network_msg_alloc(ad->len - sizeof(ad->type));

	/* Extract network packet */
	memcpy(msg, ad->data, ad->len - sizeof(ad->type));

	/* push to network layer */
	network_recv_msg(&badv->nif, msg);

	network_msg_unref(msg);
}

static void bearer_adv_recv_prov(struct bearer_adv_data *badv,
				 const struct ad_struct *ad)
{
	struct pb_adv_pdu *pbadv = (struct pb_adv_pdu *)ad->data;
	size_t len = ad->len - sizeof(ad->type) - sizeof(*pbadv);

	generic_prov_recv(&badv->gpb, be32_to_cpu(pbadv->link_id),
			  pbadv->trans_num, pbadv->gen_prov_pdu, len);
}

static void bearer_adv_recv_beacon(struct bearer_adv_data *badv,
				   const struct ad_struct *ad)
{
	g_message("Recv Beacon");

	generic_prov_recv_beacon(&badv->gpb, ad->data,
				 ad->len - sizeof(ad->type));
}

void bearer_adv_recv(struct advertiser *adv, const void *data, size_t dlen)
{
	struct bearer_adv_data *badv = adv->priv;
	const struct ad_struct *ad;
	int offset = 0;

	while (offset < dlen) {
		ad = (struct ad_struct *)(data + offset);
		if (ad->len == 0)
			break;

		offset += ad->len + 1;

		switch (ad->type) {
		case AD_TYPE_MESH_MSG:
			bearer_adv_recv_msg(badv, ad);
			break;
		case AD_TYPE_MESH_PROV:
			bearer_adv_recv_prov(badv, ad);
			break;
		case AD_TYPE_MESH_BEACON:
			bearer_adv_recv_beacon(badv, ad);
		default:
			continue;
		}
	}
}

int bearer_adv_open(struct network_intf *nif)
{
	struct bearer_adv_data *badv = nif2badv(nif);
	struct advertiser *adv = badv->adv;
	int err;

	err = adv->open(adv);
	if (err)
		return err;

	adv->scan_enable(adv, true);

	return 0;
}

void bearer_adv_close(struct network_intf *nif)
{
	struct bearer_adv_data *badv = nif2badv(nif);
	struct advertiser *adv = badv->adv;

	adv->close(adv);
}

static int bearer_adv_sendmsg(struct network_intf *nif,
			      struct network_msg *nmsg)
{
	struct bearer_adv_data *badv = nif2badv(nif);
	struct ad_struct ad;

	ad.type = AD_TYPE_MESH_MSG;
	ad.len = nmsg->len + sizeof(ad.type);
	memcpy(ad.data, nmsg, nmsg->len);

	badv->adv->add(badv->adv, &ad, ad.len + sizeof(ad.len), 0);

	return 0;
}

int bearer_adv_register_advertiser(struct advertiser *adv)
{
	struct bearer_adv_data *badv = g_new0(struct bearer_adv_data, 1);
	struct network_intf *nif = &badv->nif;
	struct generic_prov_bearer *gpb = &badv->gpb;

	badv->adv = adv;
	adv->priv = badv;

	/* Create Network Interface */
	nif->type = NET_INTF_ADV;
	sprintf(nif->name, "netadv-%d", idx);
	nif->open = bearer_adv_open;
	nif->close = bearer_adv_close;
	nif->sendmsg = bearer_adv_sendmsg;

	network_intf_register(nif);

	/* Create Provisioning Bearer Interface */
	gpb->mtu = 24;
	gpb->send = bearer_adv_prov_send;
	//gpb->scan = bearer_adv_prov_scan;
	gpb->beacon = bearer_adv_prov_beacon;
	sprintf(gpb->name, "pbadv-%d", idx++);

	generic_prov_bearer_register(&badv->gpb);

	return 0;
}

int bearer_adv_init(void)
{
	return hci_channel_init();
}
