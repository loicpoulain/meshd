/*
 *
 * Meshd, Bluetooth Smart Mesh stack for Linux
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

#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stddef.h>
#include <stdbool.h>
#include <glib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "advertiser.h"

#include "../bearer.h"
#include "../utils.h"
#include "../workqueue.h"

#include "../external/bluez/hci.h"
#include "../external/bluez/bt.h"

#define IOCTL_HCIDEVDOWN _IOW('H', 202, int)
#define BTPROTO_HCI 1

#define HCI_ADV_ENABLED 1
#define HCI_SCAN_ENABLED 2

/* for many devices max Adv NONCONN rate is 100ms */
/* Set as connectable to reach 20 ms */
#define CONNECTABLE_HACK

#define ADV_WINDOW_MS 150

#define adv2hci(p) container_of(p, struct hci_channel_data, adv)

struct hci_channel_data {
	struct advertiser adv;
	struct bt_hci *hci_dev;
	GQueue *adv_data_q;
	struct work tx_work;
	int hci_flags;
};

static void le_meta_evt_recv_cb(const void *data, uint8_t size, void *user_data)
{
	struct hci_channel_data *hci = user_data;
	uint8_t subevent = *((uint8_t *) data);
	const struct bt_hci_evt_le_adv_report *report = data + 1;

	if (subevent != BT_HCI_EVT_LE_ADV_REPORT)
		return;

	if (report->num_reports != 1) {
		g_error("FIXME: do not manage multi-report");
		return;
	}

	/* Report to bearer-adv */
	bearer_adv_recv(&hci->adv, report->data, report->data_len);
}

static void hci_init_cmd_cb(const void *data, uint8_t size, void *user_data)
{
	uint8_t status, cmd;

	/* Command Complete, data[0] = status */
	if (!size)
		return;

	status = ((uint8_t *)data)[0];
	cmd = (uintptr_t)user_data;

	if (status) {/* != success */
		g_error("init: HCI command %02x failed (status = %02x)", cmd,
			status);
		return;
	}
}

static struct bt_hci *hci_channel_create_dev(int device_index, int force)
{
	struct bt_hci *hci_dev;
	int tmp_fd;

	if (!force)
		goto open_user_channel;

	/* not the final hci socket, used to perform hci down via ioctl */
	tmp_fd = socket(PF_BLUETOOTH, SOCK_RAW, BTPROTO_HCI);
	if (tmp_fd < 0) {
		g_error("Bluetooth socket error: %s", strerror(errno));
		return NULL;
	}

	if (ioctl(tmp_fd, IOCTL_HCIDEVDOWN, device_index)) {
		g_error("Unable to force down hci%d: %s", device_index,
			 strerror(errno));
		close(tmp_fd);
		return NULL;
	}

open_user_channel:
	/* Automatically added to mainloop epoll */
	hci_dev = bt_hci_new_user_channel(device_index);
	if (!hci_dev) {
		g_error("Failed to open HCI user channel");
		if (force)
			close(tmp_fd);
		return NULL;
	}

	if (force)
		close(tmp_fd); /* don't need anymore */

	return hci_dev;
}

static int hci_channel_adv_enable(struct advertiser *adv, bool enable)
{
	struct hci_channel_data *hci = adv2hci(adv);
	struct bt_hci_cmd_le_set_adv_enable adv_enable = {
		.enable = enable ? 0x01 : 0x00,
	};

	if ((enable && (hci->hci_flags & HCI_ADV_ENABLED)) ||
	    (!enable && !(hci->hci_flags & HCI_ADV_ENABLED)))
		return -EALREADY;

	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_ADV_ENABLE, &adv_enable,
		    sizeof(adv_enable), NULL, NULL, NULL);

	if (enable)
		hci->hci_flags |= HCI_ADV_ENABLED;
	else
		hci->hci_flags &= ~HCI_ADV_ENABLED;

	return 0;
}

static int hci_channel_scan_enable(struct advertiser *adv, bool enable)
{
	struct hci_channel_data *hci = adv2hci(adv);
	struct bt_hci_cmd_le_set_scan_enable scan_enable_param = {
		.enable = enable ? 0x01 : 0x00,
		.filter_dup = 0x00,
	};

	if ((enable && (hci->hci_flags & HCI_SCAN_ENABLED)) ||
	    (!enable && !(hci->hci_flags & HCI_SCAN_ENABLED)))
		return -EALREADY;

	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_SCAN_ENABLE,
		    &scan_enable_param, sizeof(scan_enable_param), NULL, NULL,
		    NULL);

	if (enable)
    		hci->hci_flags |= HCI_SCAN_ENABLED;
    	else
    		hci->hci_flags &= ~HCI_SCAN_ENABLED;

	return 0;
}

static int hci_channel_open(struct advertiser *adv)
{
	struct hci_channel_data *hci = adv2hci(adv);
	struct bt_hci_cmd_set_event_mask event_mask_param = {
		.mask = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20 },
	};
	struct bt_hci_cmd_set_event_mask le_event_mask_param = {
		.mask = { 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
	};
	struct bt_hci_cmd_le_set_adv_parameters adv_params = {
		.min_interval = cpu_to_le16(0x00A0),
		.max_interval = cpu_to_le16(0x00B0),
		.type = 0x03, /* non conn undirected */
		.own_addr_type = 0x00,
		.direct_addr_type = 0x00,
		.direct_addr = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
		.channel_map = 0x07, /* 37, 38, 39 */
		.filter_policy = 0x00,
	};
	struct bt_hci_cmd_le_set_scan_parameters set_scan_param = {
		.type = 0x00, /* passive */
		.interval = cpu_to_le16(0x0030),
		.window = cpu_to_le16(0x0030),
		.own_addr_type = 0x00, /* public */
		.filter_policy = 0x00, /* accept all */
	};

	/* Reset controller hci stack */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_RESET, NULL, 0, hci_init_cmd_cb,
		    (void *)BT_HCI_CMD_RESET, NULL);

	/* Set controller evt mask, Enable LE meta events */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_SET_EVENT_MASK, &event_mask_param,
		    sizeof(event_mask_param), hci_init_cmd_cb,
		    (void *)BT_HCI_CMD_SET_EVENT_MASK, NULL);

	/* Set Le evt mask, Enable only adv report */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_EVENT_MASK,
		    &le_event_mask_param, sizeof(le_event_mask_param),
		    hci_init_cmd_cb, (void *)BT_HCI_CMD_LE_SET_EVENT_MASK,
		    NULL);

	/* Adv paramaters TBD */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_ADV_PARAMETERS, &adv_params,
		    sizeof(adv_params), hci_init_cmd_cb,
		    (void *)BT_HCI_CMD_LE_SET_ADV_PARAMETERS, NULL);

	/* Set scan params TBD */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_SCAN_PARAMETERS,
		    &set_scan_param, sizeof(set_scan_param), hci_init_cmd_cb,
		    (void *)BT_HCI_CMD_LE_SET_SCAN_PARAMETERS, NULL);

	/* Register callback on LE meta evt reception (adv report) */
	bt_hci_register(hci->hci_dev, BT_HCI_EVT_LE_META_EVENT,
			le_meta_evt_recv_cb, hci, NULL);

	return 0;
}

static void hci_channel_close(struct advertiser *adv)
{
	struct hci_channel_data *hci = adv2hci(adv);

	/* Reset controller hci stack */
	bt_hci_send(hci->hci_dev, BT_HCI_CMD_RESET, NULL, 0, hci_init_cmd_cb,
		    (void *)BT_HCI_CMD_RESET, NULL);
}

static void hci_channel_tx_work(struct work *work)
{
	struct hci_channel_data *hci;
	struct bt_hci_cmd_le_set_adv_data *adv_data_param;

	hci = container_of(work, struct hci_channel_data, tx_work);

	adv_data_param = g_queue_pop_head(hci->adv_data_q);
	if (adv_data_param == NULL) {
		hci_channel_adv_enable(&hci->adv, false);
		return;
	}

	hci_channel_adv_enable(&hci->adv, true);

	bt_hci_send(hci->hci_dev, BT_HCI_CMD_LE_SET_ADV_DATA, adv_data_param,
		    sizeof(*adv_data_param), NULL, NULL, NULL);

	g_free(adv_data_param);

	schedule_delayed_work(&hci->tx_work, ADV_WINDOW_MS);
}

static void hci_channel_add(struct advertiser *adv, void *data, size_t dlen,
			    int duration)
{
	struct hci_channel_data *hci = adv2hci(adv);
	struct bt_hci_cmd_le_set_adv_data *adv_data_param;

	adv_data_param = g_new(struct bt_hci_cmd_le_set_adv_data, 1);

	/* prepare parameters for upcoming BT_HCI_CMD_LE_SET_ADV_DATA */
	adv_data_param->len = dlen;
	memcpy(adv_data_param->data, data, dlen);
	memset(adv_data_param->data + dlen, 0,
	       sizeof(adv_data_param->data) - dlen); /* padding */

	g_queue_push_tail(hci->adv_data_q, adv_data_param);
	schedule_work(&hci->tx_work);
}

static int hci_channel_register(int idx)
{
	struct hci_channel_data *hci = g_new0(struct hci_channel_data, 1);

	hci->hci_dev = hci_channel_create_dev(idx, 1);
	if (!hci->hci_dev) {
		g_free(hci);
		return -EINVAL;
	}

	hci->adv_data_q = g_queue_new();
	init_work(&hci->tx_work, hci_channel_tx_work);

	hci->adv.open = hci_channel_open;
	hci->adv.close = hci_channel_close;
	hci->adv.add = hci_channel_add;
	hci->adv.scan_enable = hci_channel_scan_enable;

	if (bearer_adv_register_advertiser(&hci->adv)) {
		g_queue_free(hci->adv_data_q);
		bt_hci_unref(hci->hci_dev);
		g_free(hci);
	}

	return 0;
}

int hci_channel_init(void)
{
	/* TODO make it configurable */
	/* TODO release function (hci_unref & queue destroy) */
	return hci_channel_register(0);
}
