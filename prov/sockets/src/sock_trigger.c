/*
 * Copyright (c) 2014-2015 Intel Corporation, Inc.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include "config.h"

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sock.h"
#include "sock_util.h"

#define SOCK_LOG_DBG(...) _SOCK_LOG_DBG(FI_LOG_EP_DATA, __VA_ARGS__)
#define SOCK_LOG_ERROR(...) _SOCK_LOG_ERROR(FI_LOG_EP_DATA, __VA_ARGS__)

ssize_t sock_queue_cq_op(struct fid_cq *cq, const void *buf,
			 struct fid_cntr *cntr, uint64_t threshold)
{
	struct sock_cq *sock_cq;
	struct sock_trigger *trigger;
	struct sock_cntr *sock_cntr;

	sock_cq = container_of(cq, struct sock_cq, cq_fid);
	sock_cntr = container_of(cntr, struct sock_cntr, cntr_fid);
	if (atomic_get(&sock_cntr->value) >= threshold) {
		_sock_cq_write(sock_cq, FI_ADDR_NOTAVAIL, buf,
			       sock_cq->cq_entry_size);
		return 0;
	}

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold;
	trigger->op.cq.cq = cq;
	memcpy(&trigger->op.cq.entry, buf, sock_cq->cq_entry_size);
	trigger->op_type = SOCK_OP_CQ;

	fastlock_acquire(&sock_cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &sock_cntr->trigger_list);
	fastlock_release(&sock_cntr->trigger_lock);
	sock_cntr_check_trigger_list(sock_cntr);
	return 0;
}

ssize_t sock_queue_cntr_op(struct fid_cntr *cntr, uint64_t threshold,
			   struct fid_cntr *target_cntr, uint64_t value,
			   uint8_t op_type)
{
	struct sock_cntr *sock_cntr;
	struct sock_trigger *trigger;

	sock_cntr = container_of(cntr, struct sock_cntr, cntr_fid);
	if (atomic_get(&sock_cntr->value) >= threshold) {
		if (op_type == SOCK_OP_CNTR_SET) {
			sock_cntr_set(target_cntr, value);
		} else {
			sock_cntr_add(target_cntr, value);
		}
		return 0;
	}

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold;
	trigger->op.cntr.cntr = target_cntr;
	trigger->op.cntr.value = value;
	trigger->op_type = op_type;

	fastlock_acquire(&sock_cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &sock_cntr->trigger_list);
	fastlock_release(&sock_cntr->trigger_lock);
	sock_cntr_check_trigger_list(sock_cntr);
	return 0;
}

ssize_t sock_queue_rma_op(struct fid_ep *ep, const struct fi_msg_rma *msg,
			  uint64_t flags, uint8_t op_type,
			  struct sock_cntr **cmp_cntr)
{
	struct sock_cntr *cntr;
	struct sock_trigger *trigger;
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;

	trigger_context = (struct fi_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context)
		return -FI_EINVAL;

	threshold = &trigger_context->trigger.threshold;
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	    trigger_context->event_type == FI_TRIGGER_THRESHOLD_COMPLETION) {
		*cmp_cntr = container_of(threshold->cmp_cntr, struct sock_cntr, cntr_fid);
	} else {
		*cmp_cntr = NULL;
	}

	cntr = container_of(threshold->trig_cntr, struct sock_cntr, cntr_fid);
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     atomic_get(&cntr->value) >= threshold->threshold)
		return 1;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold->threshold;
	memcpy(&trigger->op.rma.msg, msg, sizeof(*msg));
	trigger->op.rma.msg.msg_iov = &trigger->op.rma.msg_iov[0];
	trigger->op.rma.msg.rma_iov = &trigger->op.rma.rma_iov[0];

	memcpy(&trigger->op.rma.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));
	memcpy(&trigger->op.rma.rma_iov[0], &msg->rma_iov[0],
	       msg->rma_iov_count * sizeof(struct fi_rma_iov));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	sock_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t sock_queue_msg_op(struct fid_ep *ep, const struct fi_msg *msg,
			  uint64_t flags, uint8_t op_type,
			  struct sock_cntr **cmp_cntr)
{
	struct sock_cntr *cntr;
	struct sock_trigger *trigger;
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;

	trigger_context = (struct fi_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context)
		return -FI_EINVAL;

	threshold = &trigger_context->trigger.threshold;
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     trigger_context->event_type == FI_TRIGGER_THRESHOLD_COMPLETION) {
		*cmp_cntr = container_of(threshold->cmp_cntr, struct sock_cntr, cntr_fid);
	} else {
		*cmp_cntr = NULL;
	}

	cntr = container_of(threshold->trig_cntr, struct sock_cntr, cntr_fid);
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     atomic_get(&cntr->value) >= threshold->threshold)
		return 1;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold->threshold;

	memcpy(&trigger->op.msg.msg, msg, sizeof(*msg));
	trigger->op.msg.msg.msg_iov = &trigger->op.msg.msg_iov[0];
	memcpy((void *) &trigger->op.msg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	sock_cntr_check_trigger_list(cntr);
	return 0;
}

ssize_t sock_queue_tmsg_op(struct fid_ep *ep, const struct fi_msg_tagged *msg,
			   uint64_t flags, uint8_t op_type,
			   struct sock_cntr **cmp_cntr,
			   enum fi_op op, enum fi_datatype datatype)
{
	struct sock_cntr *cntr;
	struct sock_trigger *trigger;
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;

	trigger_context = (struct fi_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context)
		return -FI_EINVAL;

	threshold = &trigger_context->trigger.threshold;
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     trigger_context->event_type == FI_TRIGGER_THRESHOLD_COMPLETION) {
		*cmp_cntr = container_of(threshold->cmp_cntr, struct sock_cntr, cntr_fid);
	} else {
		*cmp_cntr = NULL;
	}

	cntr = container_of(threshold->trig_cntr, struct sock_cntr, cntr_fid);
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     atomic_get(&cntr->value) >= threshold->threshold)
		return 1;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold->threshold;

	memcpy(&trigger->op.tmsg.msg, msg, sizeof(*msg));
	trigger->op.tmsg.msg.msg_iov = &trigger->op.tmsg.msg_iov[0];
	memcpy((void *) &trigger->op.tmsg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	trigger->op.tmsg.op = op;
	trigger->op.tmsg.datatype = datatype;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	sock_cntr_check_trigger_list(cntr);
	return 0;
}

int sock_create_sched_tmsg(struct fid_ep *ep, const struct fi_msg_tagged *msg,
			   uint64_t flags, uint8_t op_type,
			   enum fi_op op, enum fi_datatype datatype)
{
	struct sock_trigger *trig_cmd;
	struct sock_sched_ctx *sched_ctx;

	trig_cmd = calloc(1, sizeof(*trig_cmd));
	if (!trig_cmd)
		return -FI_ENOMEM;

	memcpy(&trig_cmd->op.tmsg.msg, msg, sizeof(*msg));
	trig_cmd->op.tmsg.msg.msg_iov = &trig_cmd->op.tmsg.msg_iov[0];
	memcpy((void *) &trig_cmd->op.tmsg.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct iovec));

	trig_cmd->op_type = op_type;
	trig_cmd->ep = ep;
	flags &= ~FI_SCHEDULE;
	flags |= FI_TRIGGER;
	trig_cmd->flags = flags;

	trig_cmd->op.tmsg.op = op;
	trig_cmd->op.tmsg.datatype = datatype;

	sched_ctx = calloc(1, sizeof(*sched_ctx));
	if (!sched_ctx)
		return -FI_ENOMEM;

	sched_ctx->trig_cmd = trig_cmd;

	((struct fi_context *) msg->context)->internal[0] = sched_ctx;

	return 0;
}

ssize_t sock_queue_atomic_op(struct fid_ep *ep, const struct fi_msg_atomic *msg,
			     const struct fi_ioc *comparev, size_t compare_count,
			     struct fi_ioc *resultv, size_t result_count,
			     uint64_t flags, uint8_t op_type,
			     struct sock_cntr **cmp_cntr)
{
	struct sock_cntr *cntr;
	struct sock_trigger *trigger;
	struct fi_triggered_context *trigger_context;
	struct fi_trigger_threshold *threshold;

	trigger_context = (struct fi_triggered_context *) msg->context;
	if ((flags & FI_INJECT) || !trigger_context)
		return -FI_EINVAL;

	threshold = &trigger_context->trigger.threshold;
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     trigger_context->event_type == FI_TRIGGER_THRESHOLD_COMPLETION) {
		*cmp_cntr = container_of(threshold->cmp_cntr, struct sock_cntr, cntr_fid);
	} else {
		*cmp_cntr = NULL;
	}

	cntr = container_of(threshold->trig_cntr, struct sock_cntr, cntr_fid);
	if (trigger_context->event_type == FI_TRIGGER_COMPLETION ||
	     atomic_get(&cntr->value) >= threshold->threshold)
 		return 1;

	trigger = calloc(1, sizeof(*trigger));
	if (!trigger)
		return -FI_ENOMEM;

	trigger->threshold = threshold->threshold;
	memcpy(&trigger->op.atomic.msg, msg, sizeof(*msg));
	trigger->op.atomic.msg.msg_iov = &trigger->op.atomic.msg_iov[0];
	trigger->op.atomic.msg.rma_iov = &trigger->op.atomic.rma_iov[0];

	memcpy(&trigger->op.atomic.msg_iov[0], &msg->msg_iov[0],
	       msg->iov_count * sizeof(struct fi_ioc));
	memcpy(&trigger->op.atomic.rma_iov[0], &msg->rma_iov[0],
	       msg->iov_count * sizeof(struct fi_rma_ioc));

	if (comparev) {
		memcpy(&trigger->op.atomic.comparev[0], &comparev[0],
		       compare_count * sizeof(struct fi_ioc));
	}

	if (resultv) {
		memcpy(&trigger->op.atomic.resultv[0], &resultv[0],
		       result_count * sizeof(struct fi_ioc));
	}

	trigger->op_type = op_type;
	trigger->ep = ep;
	trigger->flags = flags;

	fastlock_acquire(&cntr->trigger_lock);
	dlist_insert_tail(&trigger->entry, &cntr->trigger_list);
	fastlock_release(&cntr->trigger_lock);
	sock_cntr_check_trigger_list(cntr);
	return 0;
}

/* convert a scheduled op to a triggered op equivalent */
int sock_convert_to_trigger_op(struct sock_sched_ctx *sched_ctx,
		struct sock_sched_vertex *vertex)
{
	struct fi_triggered_context *trig_ctx;
	struct fi_sched_ops *parent_user_vertex;

	trig_ctx = &sched_ctx->trig_ctx;
	trig_ctx->trigger.threshold.cmp_cntr = &vertex->cmp_cntr->cntr_fid;

	if (vertex->parent) {
		parent_user_vertex = (struct fi_sched_ops *)
			container_of(vertex->parent, struct fi_sched_ops, reserved);
		trig_ctx->trigger.threshold.threshold = parent_user_vertex->num_ops;
		trig_ctx->trigger.threshold.trig_cntr = &vertex->parent->cmp_cntr->cntr_fid;
		trig_ctx->event_type = FI_TRIGGER_THRESHOLD_COMPLETION;
	} else {
		trig_ctx->event_type = FI_TRIGGER_COMPLETION;
	}

	switch(sched_ctx->trig_cmd->op_type) {
	case SOCK_OP_TSEND:
	case SOCK_OP_TRECV:
	case SOCK_OP_TSEND_OP:
		sched_ctx->trig_cmd->op.tmsg.msg.context = trig_ctx;
		break;
	default:
		SOCK_LOG_DBG("op type %d not supported\n",
				sched_ctx->trig_cmd->op_type);
		return -FI_EINVAL;
	}

	return 0;
}

int sock_sched_bind(struct fid *fid, struct fid *bfid, uint64_t flags)
{
	struct sock_sched *sock_sched;
	struct sock_cntr *sock_cntr;

	switch (fid->fclass) {
	case FI_CLASS_SCHED:
		sock_sched = container_of(fid, struct sock_sched, sched_fid.fid);
		break;
	default:
		return -FI_EINVAL;
	}
	switch (bfid->fclass) {
	case FI_CLASS_CNTR:
		sock_cntr = container_of(bfid, struct sock_cntr, cntr_fid.fid);
		break;
	default:
		return -FI_EINVAL;
	}

	sock_sched = container_of(fid, struct sock_sched, sched_fid);

	sock_sched->user_cmp_cntr = sock_cntr;

	return 0;
}


int sock_explore_vertex(struct sock_ep *sock_ep,
		struct sock_sched *sock_sched,
		struct sock_sched_vertex *vertex)
{
	int i, ret;
	struct sock_sched_ctx *sched_ctx;
	struct fid_cntr *cntr;
	struct sock_cntr *sock_cntr;
	struct fi_cntr_attr attr = {0};
	struct fi_sched_ops *user_vertex;

	user_vertex = container_of(vertex, struct fi_sched_ops, reserved);

	if (user_vertex->num_edges) { /* has children */
		ret = sock_cntr_open(&sock_ep->attr->domain->dom_fid,
				&attr, &cntr, NULL);
		if (ret) {
			SOCK_LOG_DBG("error opening internal counter\n");
			return ret;
		}
		sock_cntr = container_of(cntr, struct sock_cntr, cntr_fid);
		slist_insert_tail(&sock_cntr->list_entry, &sock_sched->cntrs);
	} else { /* leaf node */
		sock_sched->cmp_threshold += user_vertex->num_ops;
		sock_cntr = sock_sched->cmp_cntr;
	}

	vertex->cmp_cntr = sock_cntr;

	for(i = 0; i < user_vertex->num_ops; i++) {
		sched_ctx = (struct sock_sched_ctx *)
			user_vertex->ops[i].internal[0];

		ret = sock_convert_to_trigger_op(sched_ctx, vertex);
		if (ret) {
			SOCK_LOG_DBG("error converting to triggered op\n");
			return ret;
		}

		slist_insert_tail(&sched_ctx->list_entry, &sock_sched->ops);
	}

	return 0;
}

int sock_sched_setup(struct fid_sched *sched_fid,
		struct fi_sched_ops *sched_ops, uint64_t flags)
{
	int i, ret;
	struct slist queue;
	struct sock_ep *sock_ep;
	struct sock_sched *sock_sched;
	struct fi_sched_ops *user_vertex;
	struct slist_entry *list_entry;
	struct sock_sched_vertex *vertex, *curr_vertex;

	sock_sched = container_of(sched_fid, struct sock_sched, sched_fid);

	sock_ep = sock_sched->ep;

	if (!sock_sched->user_cmp_cntr) {
		SOCK_LOG_ERROR("No counter bound to schedule\n");
		return -FI_EINVAL;
	}

	slist_init(&queue);
	slist_init(&sock_sched->ops);
	slist_init(&sock_sched->cntrs);

	SOCK_COMPILE_ASSERT((sizeof(struct sock_sched_vertex) <=
				(sizeof(struct fi_sched_ops) -
				 offsetof(struct fi_sched_ops, reserved))));

	/* initialize root element and enqueue */
	vertex = (struct sock_sched_vertex *) &sched_ops->reserved[0];
	vertex->parent = NULL;

	ret = sock_explore_vertex(sock_ep, sock_sched, vertex);
	if (ret)
		return ret;

	slist_insert_tail(&vertex->list_entry, &queue);

	/* BFS */
	while(!slist_empty(&queue)) {

		list_entry = slist_remove_head(&queue);
		curr_vertex = container_of(list_entry,
				struct sock_sched_vertex, list_entry);
		user_vertex = container_of(curr_vertex, struct fi_sched_ops, reserved);

		for(i = 0; i < user_vertex->num_edges; i++) {
			vertex = (struct sock_sched_vertex *)
				&user_vertex->edges[i].reserved[0];
			vertex->parent = curr_vertex;

			ret = sock_explore_vertex(sock_ep, sock_sched, vertex);
			if (ret)
				return ret;
			slist_insert_tail(&vertex->list_entry, &queue);
		}
	}

	return 0;
}

int sock_sched_close(struct fid *fid)
{
	int ret;
	struct sock_sched *sock_sched;
	struct sock_cntr *sock_cntr;
	struct slist_entry *list_entry;
	struct sock_sched_ctx *sched_ctx;

	sock_sched = container_of(fid, struct sock_sched, sched_fid);

	while (!slist_empty(&sock_sched->ops)) {
		list_entry = slist_remove_head(&sock_sched->ops);
		sched_ctx = container_of(list_entry, struct sock_sched_ctx, list_entry);

		free(sched_ctx->trig_cmd);
		free(sched_ctx);
	}

	while (!slist_empty(&sock_sched->cntrs)) {
		list_entry = slist_remove_head(&sock_sched->cntrs);
		sock_cntr = container_of(list_entry, struct sock_cntr, list_entry);

		ret = fi_close(&sock_cntr->cntr_fid.fid);
		if (ret)
			return ret;
	}

	ret = fi_close(&sock_sched->cmp_cntr->cntr_fid.fid);
	if (ret)
		return ret;

	free(sock_sched);

	return 0;
}

int sock_sched_run(struct fid_sched *sched_fid)
{
	int ret;
	uint64_t cmp_threshold;
	struct sock_cntr *sock_cntr;
	struct sock_sched *sock_sched;
	struct slist_entry *list_entry;
	struct sock_sched_ctx *sched_ctx;

	sock_sched = container_of(sched_fid, struct sock_sched, sched_fid);

	cmp_threshold = fi_cntr_read(&sock_sched->cmp_cntr->cntr_fid) + 1;

	if (sock_sched->used) {
		/* we need to reset all the completion counters */
		for (list_entry = sock_sched->cntrs.head; list_entry;
				list_entry = list_entry->next) {
			sock_cntr = container_of(list_entry, struct sock_cntr, list_entry);
			ret = fi_cntr_set(&sock_cntr->cntr_fid, 0);
			if (ret)
				return ret;
		}
	} else {
		sock_sched->used = 1;
	}

	for (list_entry = sock_sched->ops.head; list_entry;
			list_entry = list_entry->next)
	{
		sched_ctx = container_of(list_entry, struct sock_sched_ctx, list_entry);
		switch(sched_ctx->trig_cmd->op_type) {
		case SOCK_OP_TSEND:
			ret = sock_ep_tsendmsg(&sock_sched->ep->ep,
					&sched_ctx->trig_cmd->op.tmsg.msg,
					sched_ctx->trig_cmd->flags |
					SOCK_NO_COMPLETION);
			if (ret)
				return ret;
			break;
		case SOCK_OP_TRECV:
			ret = sock_ep_trecvmsg(&sock_sched->ep->ep,
					&sched_ctx->trig_cmd->op.tmsg.msg,
					sched_ctx->trig_cmd->flags |
					SOCK_NO_COMPLETION);
			if (ret)
				return ret;
			break;
		case SOCK_OP_TSEND_OP:
			ret = sock_ep_tsendmsg_common(&sock_sched->ep->ep,
					&sched_ctx->trig_cmd->op.tmsg.msg,
					sched_ctx->trig_cmd->flags |
					SOCK_NO_COMPLETION,
					sched_ctx->trig_cmd->op.tmsg.op,
					sched_ctx->trig_cmd->op.tmsg.datatype);
			break;
		default:
			return -FI_ENOSYS;
		}
	}

	ret = fi_cntr_trig_add(&sock_sched->cmp_cntr->cntr_fid,
			cmp_threshold,
			&sock_sched->user_cmp_cntr->cntr_fid, 1);
	if (ret)
		return ret;

	return 0;
}
