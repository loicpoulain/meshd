#include "../node.h"
#include "../network.h"

#ifndef __INTERFACE_H
#define __INTERFACE_H

/* TODO flag this */
int cmdline_init(int input, int output);

struct user_interface{
	char *name;
	void (*network_recv)(struct network *, struct network_msg *);
	void (*network_add)(struct network *);
};

static inline void user_intf_network_recv(struct network *net,
					  const struct network_msg *msg)
{
	GSList *l;

	for (l = node.interface_l; l != NULL; l = l->next) {
		struct user_interface *intf = l->data;

		if (intf->network_recv) {
			struct network_msg *nmsg = network_msg_clone(msg);
			intf->network_recv(net, nmsg);
			network_msg_unref(nmsg);
		}
	}
}

static inline void user_intf_network_added(struct network *net)
{
	GSList *l;

	for (l = node.interface_l; l != NULL; l = l->next) {
		struct user_interface *intf = l->data;

		if (intf->network_add)
			intf->network_add(net);
	}
}

static inline int register_user_intf(struct user_interface *intf)
{
	node.interface_l = g_slist_append(node.interface_l, intf);
	g_message("User interface %s registered", intf->name);
}

#endif
