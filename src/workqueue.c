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

#include "workqueue.h"

/* TODO: Reworking & optimization */

static GQueue main_q = G_QUEUE_INIT;

static inline unsigned int get_time_ms(void)
{
	struct timespec tp;

	if (clock_gettime(CLOCK_MONOTONIC, &tp))
		return -EINVAL;

	return tp.tv_sec * 1000 + tp.tv_nsec / 1000 / 1000;
}

static gint work_need_run(gconstpointer a, gconstpointer b)
{
	const struct work *work = a;
	const unsigned long *ms = b;

	if (!work->ms_target || (work->ms_target <= *ms))
		return 0;

	return -1;
}

static gboolean workqueue_routine(gpointer user_data);
static void workqueue_schedule(void)
{
	unsigned int now = get_time_ms();
	unsigned int delay_ms = -1;
	GList *l;

	for (l = g_queue_peek_head_link(&main_q); l != NULL; l = l->next) {
		struct work *work = l->data;
		int wdelay = work->ms_target - now;

		if (wdelay < 0) {
			delay_ms = 0;
			break;
		}

		if (wdelay < delay_ms)
			delay_ms = wdelay;
	}

	/* no work to schedule */
	if (delay_ms == -1)
		return;

	/* TODO fix this workaround */
	/* if (delay_ms == 0)
		delay_ms = 1; */

	/* TODO: Improve GSource re-usage, only modify timeout */
	g_timeout_add(delay_ms, workqueue_routine, NULL);
}

static gboolean workqueue_routine(gpointer user_data)
{
	struct work *work;
	unsigned long now;

	if (g_queue_is_empty(&main_q))
		return FALSE;

	now = get_time_ms();

	while (1) {
		GList *l = g_queue_find_custom(&main_q, &now, work_need_run);

		if (l == NULL)
			break;

		work = l->data;

		g_queue_delete_link(&main_q, l);

		work->func(work);
	}

	workqueue_schedule();

	return FALSE;
}

int init_work(struct work *work, void (*func)(struct work *))
{
	work->func = func;

	return 0;
}

int schedule_delayed_work(struct work *work, unsigned int delay_ms)
{
	if (g_queue_find(&main_q, work))
		return 0; /* already scheduled */

	if (!delay_ms)
		work->ms_target = 0;
	else
		work->ms_target = get_time_ms() + delay_ms;

	g_queue_push_tail(&main_q, work);

	workqueue_schedule();

	return 0;
}

int schedule_work(struct work *work)
{
	return schedule_delayed_work(work, 0);
}

void cancel_work(struct work *work)
{
	g_queue_remove(&main_q, work);
}

bool is_scheduled(struct work *work)
{
	if (g_queue_find(&main_q, work))
		return true;

	return false;
}
