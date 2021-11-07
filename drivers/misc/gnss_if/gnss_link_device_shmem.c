/*
 * Copyright (C) 2010 Samsung Electronics.
 *
 * This software is licensed under the terms of the GNU General Public
 * License version 2, as published by the Free Software Foundation, and
 * may be copied, distributed, and modified under those terms.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/irq.h>
#include <linux/gpio.h>
#include <linux/time.h>
#include <linux/interrupt.h>
#include <linux/timer.h>
#include <linux/wakelock.h>
#include <linux/delay.h>
#include <linux/wait.h>
#include <linux/sched.h>
#include <linux/vmalloc.h>
#include <linux/if_arp.h>
#include <linux/platform_device.h>
#include <linux/kallsyms.h>
#include <linux/suspend.h>
#include <linux/notifier.h>
#include <linux/smc.h>

#include <linux/skbuff.h>
#ifdef CONFIG_OF_RESERVED_MEM
#include <linux/of_reserved_mem.h>
#endif

#include "include/gnss.h"
#include "gnss_link_device_shmem.h"
#include "../mcu_ipc/mcu_ipc.h"

#include "gnss_prj.h"

struct shmem_conf shmem_conf;

/**
 * recv_int2ap
 * @shmd: pointer to an instance of shmem_link_device structure
 *
 * Returns the value of the GNSS-to-AP interrupt register.
 */
static inline u16 recv_int2ap(struct shmem_link_device *shmd)
{
	return (u16)mbox_get_value(MCU_GNSS, shmd->irq_gnss2ap_ipc_msg);
}

/**
 * send_int2cp
 * @shmd: pointer to an instance of shmem_link_device structure
 * @mask: value to be written to the AP-to-GNSS interrupt register
 */
static inline void send_int2gnss(struct shmem_link_device *shmd, u16 mask)
{
	mbox_set_value(MCU_GNSS, shmd->reg_tx_ipc_msg, mask);
	mbox_set_interrupt(MCU_GNSS, shmd->int_ap2gnss_ipc_msg);
}

/**
 * get_shmem_status
 * @shmd: pointer to an instance of shmem_link_device structure
 * @dir: direction of communication (TX or RX)
 * @mst: pointer to an instance of mem_status structure
 *
 * Takes a snapshot of the current status of a SHMEM.
 */
static void get_shmem_status(struct shmem_link_device *shmd,
		enum direction dir, struct mem_status *mst)
{
	mst->dir = dir;
	mst->head[TX] = get_txq_head(shmd);
	mst->tail[TX] = get_txq_tail(shmd);
	mst->head[RX] = get_rxq_head(shmd);
	mst->tail[RX] = get_rxq_tail(shmd);
	mst->int2ap = recv_int2ap(shmd);
	mst->int2gnss = read_int2gnss(shmd);

	gif_debug("----- %s -----\n", __func__);
	gif_debug("%s: mst->dir      = %d\n", __func__, mst->dir);
	gif_debug("%s: mst->head[TX] = %d\n", __func__, mst->head[TX]);
	gif_debug("%s: mst->tail[TX] = %d\n", __func__, mst->tail[TX]);
	gif_debug("%s: mst->head[RX] = %d\n", __func__, mst->head[RX]);
	gif_debug("%s: mst->tail[RX] = %d\n", __func__, mst->tail[RX]);
	gif_debug("%s: mst->int2ap   = %d\n", __func__, mst->int2ap);
	gif_debug("%s: mst->int2gnss = %d\n", __func__, mst->int2gnss);
	gif_debug("----- %s -----\n", __func__);
}

static inline void update_rxq_tail_status(struct shmem_link_device *shmd,
                                          struct mem_status *mst)
{
	mst->tail[RX] = get_rxq_tail(shmd);
}

/**
 * ipc_rx_work
 * @ws: pointer to an instance of work_struct structure
 *
 * Invokes the recv method in the io_device instance to perform receiving IPC
 * messages from each skb.
 */
static void msg_rx_work(struct work_struct *ws)
{
	struct shmem_link_device *shmd;
	struct link_device *ld;
	struct io_device *iod;
	struct sk_buff *skb;

	shmd = container_of(ws, struct shmem_link_device, msg_rx_dwork.work);
	ld = &shmd->ld;

	iod = ld->iod;
	while (1) {
		skb = skb_dequeue(ld->skb_rxq);
		if (!skb)
			break;
		if (iod->recv_skb_single)
			iod->recv_skb_single(iod, ld, skb);
		else
			gif_err("ERR! iod->recv_skb_single undefined!\n");
	}
}

/**
 * rx_ipc_frames
 * @shmd: pointer to an instance of shmem_link_device structure
 * @mst: pointer to an instance of mem_status structure
 *
 * Returns
 *   ret < 0  : error
 *   ret == 0 : ILLEGAL status
 *   ret > 0  : valid data
 *
 * Must be invoked only when there is data in the corresponding RXQ.
 *
 * Requires a recv_skb method in the io_device instance, so this function must
 * be used for only EXYNOS.
 */
static int rx_ipc_frames(struct shmem_link_device *shmd,
			struct circ_status *circ)
{
	struct link_device *ld = &shmd->ld;
	struct io_device *iod;
	struct sk_buff_head *rxq = ld->skb_rxq;
	struct sk_buff *skb;
	/**
	 * variables for the status of the circular queue
	 */
	u8 *src;
	u8 hdr[EXYNOS_HEADER_SIZE];
	/**
	 * variables for RX processing
	 */
	int qsize;	/* size of the queue			*/
	int rcvd;	/* size of data in the RXQ or error	*/
	int rest;	/* size of the rest data		*/
	int out;	/* index to the start of current frame	*/
	int tot;	/* total length including padding data	*/

	src = circ->buff;
	qsize = circ->qsize;
	out = circ->out;
	rcvd = circ->size;

	rest = circ->size;
	tot = 0;

	while (rest > 0) {
		u8 ch;

		/* Copy the header in the frame to the header buffer */
		circ_read(hdr, src, qsize, out, EXYNOS_HEADER_SIZE);

		/*
		gif_err("src : 0x%p, out : 0x%x, recvd : 0x%x, qsize : 0x%x\n",
				src, out, rcvd, qsize);
		*/

		/* Check the config field in the header */
		if (unlikely(!exynos_start_valid(hdr))) {
			gif_err("%s: ERR! %s INVALID config 0x%02X (rcvd %d, rest %d)\n",
				ld->name, "FMT", hdr[0],
				rcvd, rest);
			goto bad_msg;
		}

		/* Verify the total length of the frame (data + padding) */
		tot = exynos_get_total_len(hdr);
		if (unlikely(tot > rest)) {
			gif_err("%s: ERR! %s tot %d > rest %d (rcvd %d)\n",
				ld->name, "FMT", tot, rest, rcvd);
			goto bad_msg;
		}

		/* Allocate an skb */
		skb = dev_alloc_skb(tot);
		if (!skb) {
			gif_err("%s: ERR! %s dev_alloc_skb(%d) fail\n",
				ld->name, "FMT", tot);
			goto no_mem;
		}

		/* Set the attribute of the skb as "single frame" */
		skbpriv(skb)->single_frame = true;

		/* Read the frame from the RXQ */
		circ_read(skb_put(skb, tot), src, qsize, out, tot);

		/* Store the skb to the corresponding skb_rxq */
		skb_queue_tail(rxq, skb);

		ch = exynos_get_ch(skb->data);
		iod = ld->iod;
		if (!iod) {
			gif_err("%s: ERR! no IPC_BOOT iod\n", ld->name);
			break;
		}

		skbpriv(skb)->lnk_hdr = iod->link_header;
		skbpriv(skb)->exynos_ch = ch;

		/* Calculate new out value */
		rest -= tot;
		out += tot;
		if (unlikely(out >= qsize))
			out -= qsize;
	}

	/* Update tail (out) pointer to empty out the RXQ */
	set_rxq_tail(shmd, circ->in);
	return rcvd;

no_mem:
	/* Update tail (out) pointer to the frame to be read in the future */
	set_rxq_tail(shmd, out);
	rcvd -= rest;
	return rcvd;

bad_msg:
	return -EBADMSG;
}

/**
 * msg_handler: receives IPC messages from every RXQ
 * @shmd: pointer to an instance of shmem_link_device structure
 * @mst: pointer to an instance of mem_status structure
 *
 * 1) Receives all IPC message frames currently in every IPC RXQ.
 * 2) Sends RES_ACK responses if there are REQ_ACK requests from a GNSS.
 * 3) Completes all threads waiting for the corresponding RES_ACK from a GNSS if
 *    there is any RES_ACK response.
 */
static void msg_handler(struct shmem_link_device *shmd, struct mem_status *mst)
{
	struct link_device *ld = &shmd->ld;
	struct circ_status circ;
	int ret = 0;

	/*
	if (!ipc_active(shmd)) {
		gif_err("%s: ERR! IPC is NOT ACTIVE!!!\n", ld->name);
		trigger_forced_cp_crash(shmd);
		return;
	}
	*/

	/* Skip RX processing if there is no data in the RXQ */
	if (mst->head[RX] == mst->tail[RX]) {
		/* Release wakelock */
		/* Write 0x0 to mbox register 6 */
		/* done_req_ack(shmd); */
		return;

	}

	/* Get the size of data in the RXQ */
	ret = get_rxq_rcvd(shmd, mst, &circ);
	if (unlikely(ret < 0)) {
		gif_err("%s: ERR! get_rxq_rcvd fail (err %d)\n",
			ld->name, ret);
		return;
	}

	/* Read data in the RXQ */
	ret = rx_ipc_frames(shmd, &circ);
	if (unlikely(ret < 0)) {
		return;
	}
}

/**
 * ipc_rx_task: processes a SHMEM command or receives IPC messages
 * @shmd: pointer to an instance of shmem_link_device structure
 * @mst: pointer to an instance of mem_status structure
 *
 * Invokes cmd_handler for commands or msg_handler for IPC messages.
 */
static void ipc_rx_task(unsigned long data)
{
	struct shmem_link_device *shmd = (struct shmem_link_device *)data;

	while (1) {
		struct mem_status *mst;

		mst = gnss_msq_get_data_slot(&shmd->rx_msq);
		if (!mst)
			break;
		memset(mst, 0, sizeof(struct mem_status));

		get_shmem_status(shmd, RX, mst);

		/* Update tail variables with the current tail pointers */
		//update_rxq_tail_status(shmd, mst);

		msg_handler(shmd, mst);

		queue_delayed_work(system_wq, &shmd->msg_rx_dwork, 0);
	}
}

/**
 * shmem_irq_handler: interrupt handler for a MCU_IPC interrupt
 * @data: pointer to a data
 *
 * 1) Reads the interrupt value
 * 2) Performs interrupt handling
 *
 * Flow for normal interrupt handling:
 *   shmem_irq_handler -> udl_handler
 *   shmem_irq_handler -> ipc_rx_task -> msg_handler -> rx_ipc_frames ->  ...
 */
static void shmem_irq_msg_handler(void *data)
{
	struct shmem_link_device *shmd = (struct shmem_link_device *)data;
	//struct mem_status *mst = gnss_msq_get_free_slot(&shmd->rx_msq);

	gnss_msq_get_free_slot(&shmd->rx_msq);

	/*
	intr = recv_int2ap(shmd);
	if (unlikely(!INT_VALID(intr))) {
		gif_debug("%s: ERR! invalid intr 0x%X\n", ld->name, intr);
		return;
	}
	*/

	tasklet_hi_schedule(&shmd->rx_tsk);
}

static void shmem_irq_bcmd_handler(void *data)
{
	struct shmem_link_device *shmd = (struct shmem_link_device *)data;
	struct link_device *ld = (struct link_device *)&shmd->ld;
	u16 intr;

#ifndef USE_SIMPLE_WAKE_LOCK
	if (wake_lock_active(&shmd->wlock))
		wake_unlock(&shmd->wlock);
#endif

	intr = mbox_get_value(MCU_GNSS, shmd->irq_gnss2ap_bcmd);

	/* Signal kepler_req_bcmd */
	complete(&ld->bcmd_cmpl);
}

/**
 * write_ipc_to_txq
 * @shmd: pointer to an instance of shmem_link_device structure
 * @circ: pointer to an instance of circ_status structure
 * @skb: pointer to an instance of sk_buff structure
 *
 * Must be invoked only when there is enough space in the TXQ.
 */
static void write_ipc_to_txq(struct shmem_link_device *shmd,
			struct circ_status *circ, struct sk_buff *skb)
{
	u32 qsize = circ->qsize;
	u32 in = circ->in;
	u8 *buff = circ->buff;
	u8 *src = skb->data;
	u32 len = skb->len;

	/* Print send data to GNSS */
	/* gnss_log_ipc_pkt(skb, TX); */

	/* Write data to the TXQ */
	circ_write(buff, src, qsize, in, len);

	/* Update new head (in) pointer */
	set_txq_head(shmd, circ_new_pointer(qsize, in, len));
}

/**
 * xmit_ipc_msg
 * @shmd: pointer to an instance of shmem_link_device structure
 *
 * Tries to transmit IPC messages in the skb_txq of @dev as many as possible.
 *
 * Returns total length of IPC messages transmit or an error code.
 */
static int xmit_ipc_msg(struct shmem_link_device *shmd)
{
	struct link_device *ld = &shmd->ld;
	struct sk_buff_head *txq = ld->skb_txq;
	struct sk_buff *skb;
	unsigned long flags;
	struct circ_status circ;
	int space;
	int copied = 0;
	bool chk_nospc = false;

	/* Acquire the spin lock for a TXQ */
	spin_lock_irqsave(&shmd->tx_lock, flags);

	while (1) {
		/* Get the size of free space in the TXQ */
		space = get_txq_space(shmd, &circ);
		if (unlikely(space < 0)) {
			/* Empty out the TXQ */
			reset_txq_circ(shmd);
			copied = -EIO;
			break;
		}

		skb = skb_dequeue(txq);
		if (unlikely(!skb))
			break;

		/* CAUTION : Uplink size is limited to 16KB and
			     this limitation is used ONLY in North America Prj.
		   Check the free space size,
		  - FMT : comparing with skb->len
		  - RAW : check used buffer size  */
		chk_nospc = (space < skb->len) ? true : false;
		if (unlikely(chk_nospc)) {
			/* Set res_required flag */
			atomic_set(&shmd->res_required, 1);

			/* Take the skb back to the skb_txq */
			skb_queue_head(txq, skb);

			gif_err("%s: <by %pf> NOSPC in %s_TXQ {qsize:%u in:%u out:%u} free:%u < len:%u\n",
				ld->name, CALLER, "FMT",
				circ.qsize, circ.in, circ.out, space, skb->len);
			copied = -ENOSPC;
			break;
		}

		/* TX only when there is enough space in the TXQ */
		write_ipc_to_txq(shmd, &circ, skb);
		copied += skb->len;
		dev_kfree_skb_any(skb);
	}

	/* Release the spin lock */
	spin_unlock_irqrestore(&shmd->tx_lock, flags);

	return copied;
}

/**
 * fmt_tx_work: performs TX for FMT IPC device under SHMEM flow control
 * @ws: pointer to an instance of the work_struct structure
 *
 * 1) Starts waiting for RES_ACK of FMT IPC device.
 * 2) Returns immediately if the wait is interrupted.
 * 3) Restarts SHMEM flow control if there is a timeout from the wait.
 * 4) Otherwise, it performs processing RES_ACK for FMT IPC device.
 */
static void fmt_tx_work(struct work_struct *ws)
{
	struct link_device *ld;
	ld = container_of(ws, struct link_device, fmt_tx_dwork.work);

	queue_delayed_work(ld->tx_wq, ld->tx_dwork, 0);
	return;
}

/**
 * shmem_send_ipc
 * @shmd: pointer to an instance of shmem_link_device structure
 * @skb: pointer to an skb that will be transmitted
 *
 * 1) Tries to transmit IPC messages in the skb_txq with xmit_ipc_msg().
 * 2) Sends an interrupt to GNSS if there is no error from xmit_ipc_msg().
 * 3) Starts SHMEM flow control if xmit_ipc_msg() returns -ENOSPC.
 */
static int shmem_send_ipc(struct shmem_link_device *shmd)
{
	struct link_device *ld = &shmd->ld;
	int ret;

	if (atomic_read(&shmd->res_required) > 0) {
		gif_err("%s: %s_TXQ is full\n", ld->name, "FMT");
		return 0;
	}

	ret = xmit_ipc_msg(shmd);
	if (likely(ret > 0)) {
		send_int2gnss(shmd, 0x82);
		goto exit;
	}

	/* If there was no TX, just exit */
	if (ret == 0)
		goto exit;

	/* At this point, ret < 0 */
	if (ret == -ENOSPC || ret == -EBUSY) {
		/*----------------------------------------------------*/
		/* shmd->res_required was set in xmit_ipc_msg(). */
		/*----------------------------------------------------*/

		queue_delayed_work(ld->tx_wq, ld->tx_dwork,
				   msecs_to_jiffies(1));
	}

exit:
	return ret;
}

/**
 * shmem_try_send_ipc
 * @shmd: pointer to an instance of shmem_link_device structure
 * @iod: pointer to an instance of the io_device structure
 * @skb: pointer to an skb that will be transmitted
 *
 * 1) Enqueues an skb to the skb_txq for @dev in the link device instance.
 * 2) Tries to transmit IPC messages with shmem_send_ipc().
 */
static void shmem_try_send_ipc(struct shmem_link_device *shmd,
			struct io_device *iod, struct sk_buff *skb)
{
	struct link_device *ld = &shmd->ld;
	struct sk_buff_head *txq = ld->skb_txq;
	int ret;

	if (unlikely(txq->qlen >= MAX_SKB_TXQ_DEPTH)) {
		gif_err("%s: %s txq->qlen %d >= %d\n", ld->name,
			"FMT", txq->qlen, MAX_SKB_TXQ_DEPTH);
		dev_kfree_skb_any(skb);
		return;
	}

	skb_queue_tail(txq, skb);

	ret = shmem_send_ipc(shmd);
	if (ret < 0) {
		gif_err("%s->%s: ERR! shmem_send_ipc fail (err %d)\n",
			iod->name, ld->name, ret);
	}
}

/**
 * shmem_send
 * @ld: pointer to an instance of the link_device structure
 * @iod: pointer to an instance of the io_device structure
 * @skb: pointer to an skb that will be transmitted
 *
 * Returns the length of data transmitted or an error code.
 *
 * Normal call flow for an IPC message:
 *   shmem_try_send_ipc -> shmem_send_ipc -> xmit_ipc_msg -> write_ipc_to_txq
 *
 * Call flow on congestion in a IPC TXQ:
 *   shmem_try_send_ipc -> shmem_send_ipc -> xmit_ipc_msg ,,, queue_delayed_work
 *   => xxx_tx_work -> wait_for_res_ack
 *   => msg_handler
 *   => process_res_ack -> xmit_ipc_msg (,,, queue_delayed_work ...)
 */
static int shmem_send(struct link_device *ld, struct io_device *iod,
			struct sk_buff *skb)
{
	struct shmem_link_device *shmd = to_shmem_link_device(ld);
	int len = skb->len;

#ifndef USE_SIMPLE_WAKE_LOCK
	wake_lock_timeout(&shmd->wlock, IPC_WAKELOCK_TIMEOUT);
#endif

	shmem_try_send_ipc(shmd, iod, skb);

	return len;
}

static void shmem_remap_2mb_ipc_region(struct shmem_link_device *shmd)
{
	struct shmem_2mb_phys_map *map;
	struct shmem_ipc_device *dev;
	struct gnss_data *gnss;

	gnss = shmd->ld.mdm_data;

	map = (struct shmem_2mb_phys_map *)shmd->base;

	/* FMT */
	dev = &shmd->ipc_map.dev;

	dev->txq.buff = (u8 __iomem *)&map->fmt_tx_buff[0];
	dev->txq.size = SHM_2M_FMT_TX_BUFF_SZ;

	dev->rxq.buff = (u8 __iomem *)&map->fmt_rx_buff[0];
	dev->rxq.size = SHM_2M_FMT_RX_BUFF_SZ;
}

static int shmem_init_ipc_map(struct shmem_link_device *shmd)
{
	struct gnss_data *gnss = shmd->ld.mdm_data;
	int i;

	shmem_remap_2mb_ipc_region(shmd);

	memset(shmd->base, 0, shmd->size);

	shmd->dev = &shmd->ipc_map.dev;

	/* Retrieve SHMEM MBOX#, IRQ#, etc. */
	shmd->int_ap2gnss_bcmd = gnss->mbx->int_ap2gnss_bcmd;
	shmd->int_ap2gnss_ipc_msg = gnss->mbx->int_ap2gnss_ipc_msg;

	shmd->irq_gnss2ap_bcmd = gnss->mbx->irq_gnss2ap_bcmd;
	shmd->irq_gnss2ap_ipc_msg = gnss->mbx->irq_gnss2ap_ipc_msg;

	for (i = 0; i < BCMD_CTRL_COUNT; i++) {
		shmd->reg_bcmd_ctrl[i] = gnss->mbx->reg_bcmd_ctrl[i];
	}

	shmd->reg_tx_ipc_msg = gnss->mbx->reg_tx_ipc_msg;
	shmd->reg_rx_ipc_msg = gnss->mbx->reg_rx_ipc_msg;

	shmd->reg_rx_head = gnss->mbx->reg_rx_head;
	shmd->reg_rx_tail = gnss->mbx->reg_rx_tail;
	shmd->reg_tx_head = gnss->mbx->reg_tx_head;
	shmd->reg_tx_tail = gnss->mbx->reg_tx_tail;

	for (i = 0; i < FAULT_INFO_COUNT; i++) {
		shmd->reg_fault_info[i] = gnss->mbx->reg_fault_info[i];
	}

	return 0;
}

void __iomem *gnss_shm_request_region(unsigned int sh_addr,
		unsigned int size)
{
	int i;
	struct page **pages;
	void *pv;

	pages = kmalloc((size >> PAGE_SHIFT) * sizeof(*pages), GFP_KERNEL);
	if (!pages)
		return NULL;

	for (i = 0; i < (size >> PAGE_SHIFT); i++) {
		pages[i] = phys_to_page(sh_addr);
		sh_addr += PAGE_SIZE;
	}

	pv = vmap(pages, size >> PAGE_SHIFT, VM_MAP,
	pgprot_writecombine(PAGE_KERNEL));

	kfree(pages);
	return (void __iomem *)pv;
}

void gnss_release_sh_region(void *rgn)
{
	vunmap(rgn);
}

int kepler_req_bcmd(struct link_device *ld, u16 cmd_id, u16 flags,
		u32 param1, u32 param2)
{
	struct shmem_link_device *shmd = to_shmem_link_device(ld);
	u32 ctrl[BCMD_CTRL_COUNT], ret_val;
	unsigned long timeout = msecs_to_jiffies(REQ_BCMD_TIMEOUT);
	int ret;

#ifndef USE_SIMPLE_WAKE_LOCK
	wake_lock_timeout(&shmd->wlock, BCMD_WAKELOCK_TIMEOUT);
#endif
	/* Parse arguments */
	/* Flags: Command flags */
	/* Param1/2 : Paramter 1/2 */

	ctrl[CTRL0] = (flags << 16) + cmd_id;
	ctrl[CTRL1] = param1;
	ctrl[CTRL2] = param2;
	gif_debug("%s : set param  0 : 0x%x, 1 : 0x%x, 2 : 0x%x\n",
			__func__, ctrl[CTRL0], ctrl[CTRL1], ctrl[CTRL2]);
	mbox_set_value(MCU_GNSS, shmd->reg_bcmd_ctrl[CTRL0], ctrl[CTRL0]);
	mbox_set_value(MCU_GNSS, shmd->reg_bcmd_ctrl[CTRL1], ctrl[CTRL1]);
	mbox_set_value(MCU_GNSS, shmd->reg_bcmd_ctrl[CTRL2], ctrl[CTRL2]);
	/*
	 * 0xff is MAGIC number to avoid confuging that
	 * register is set from Kepler.
	 */
	mbox_set_value(MCU_GNSS, shmd->reg_bcmd_ctrl[CTRL3], 0xff);

	mbox_set_interrupt(MCU_GNSS, shmd->int_ap2gnss_bcmd);

	if (ld->gc->gnss_state == STATE_OFFLINE) {
		gif_debug("Set POWER ON!!!!\n");
		ld->gc->ops.gnss_power_on(ld->gc);
	} else if (ld->gc->gnss_state == STATE_HOLD_RESET) {
		purge_txq(ld);
		purge_rxq(ld);
		clear_shmem_map(shmd);
		gif_debug("Set RELEASE RESET!!!!\n");
		ld->gc->ops.gnss_release_reset(ld->gc);
	}

	if (cmd_id == 0x4) /* BLC_Branch does not have return value */
		return 0;

	ret = wait_for_completion_interruptible_timeout(&ld->bcmd_cmpl,
						timeout);
	if (ret == 0) {
#ifndef USE_SIMPLE_WAKE_LOCK
		wake_unlock(&shmd->wlock);
#endif
		gif_err("%s: bcmd TIMEOUT!\n", ld->name);
		return -EIO;
	}

	ret_val = mbox_get_value(MCU_GNSS, shmd->reg_bcmd_ctrl[CTRL3]);
	gif_debug("BCMD cmd_id 0x%x returned 0x%x\n", cmd_id, ret_val);

	return ret_val;
}

#ifdef CONFIG_OF_RESERVED_MEM
static int __init gnss_if_reserved_mem_setup(struct reserved_mem *remem)
{
   pr_debug("%s: memory reserved: paddr=%#lx, t_size=%zd\n",
        __func__, (unsigned long)remem->base, (size_t)remem->size);

   shmem_conf.shmem_base = remem->base;
   shmem_conf.shmem_size = remem->size;

   return 0;
}
RESERVEDMEM_OF_DECLARE(gnss_if, "exynos7870,gnss_if", gnss_if_reserved_mem_setup);
#endif

struct link_device *gnss_shmem_create_link_device(struct platform_device *pdev)
{
	struct shmem_link_device *shmd = NULL;
	struct link_device *ld = NULL;
	struct gnss_data *gnss = NULL;
	struct device *dev = &pdev->dev;
	int err = 0;
	gif_debug("+++\n");

	/* Get the gnss (platform) data */
	gnss = (struct gnss_data *)dev->platform_data;
	if (!gnss) {
		gif_err("ERR! gnss == NULL\n");
		return NULL;
	}
	gif_err("%s: %s\n", "SHMEM", gnss->name);

	if (!gnss->mbx) {
		gif_err("%s: ERR! %s->mbx == NULL\n",
			"SHMEM", gnss->name);
		return NULL;
	}

	/* Alloc an instance of shmem_link_device structure */
	shmd = devm_kzalloc(dev, sizeof(struct shmem_link_device), GFP_KERNEL);
	if (!shmd) {
		gif_err("%s: ERR! shmd kzalloc fail\n", "SHMEM");
		goto error;
	}
	ld = &shmd->ld;

	/* Retrieve gnss data and SHMEM control data from the gnss data */
	ld->mdm_data = gnss;
	ld->timeout_cnt = 0;
	ld->name = "GNSS_SHDMEM";

	/* Set attributes as a link device */
	ld->send = shmem_send;
	ld->req_bcmd = kepler_req_bcmd;

	skb_queue_head_init(&ld->sk_fmt_tx_q);
	ld->skb_txq = &ld->sk_fmt_tx_q;

	skb_queue_head_init(&ld->sk_fmt_rx_q);
	ld->skb_rxq = &ld->sk_fmt_rx_q;

	/* Initialize GNSS Reserved mem */
	gnss->gnss_base = gnss_shm_request_region(gnss->shmem_base,
			gnss->ipcmem_offset);
	if (!gnss->gnss_base) {
		gif_err("%s: ERR! gnss_reserved_region fail\n", ld->name);
		goto error;
	}
	gif_err("%s: gnss phys_addr:0x%08X virt_addr:0x%p size: %d\n", ld->name,
		gnss->shmem_base, gnss->gnss_base, gnss->ipcmem_offset);

	shmd->start = gnss->shmem_base + gnss->ipcmem_offset;
	shmd->size = gnss->ipc_size;
	shmd->base = gnss_shm_request_region(shmd->start, shmd->size);
	if (!shmd->base) {
		gif_err("%s: ERR! gnss_shm_request_region fail\n", ld->name);
		goto error;
	}
	gif_err("%s: phys_addr:0x%08X virt_addr:0x%8p size:%d\n",
		ld->name, shmd->start, shmd->base, shmd->size);

	/* Initialize SHMEM maps (physical map -> logical map) */
	err = shmem_init_ipc_map(shmd);
	if (err < 0) {
		gif_err("%s: ERR! shmem_init_ipc_map fail (err %d)\n",
			ld->name, err);
		goto error;
	}

#ifndef USE_SIMPLE_WAKE_LOCK
	/* Initialize locks, completions, and bottom halves */
	snprintf(shmd->wlock_name, MIF_MAX_NAME_LEN, "%s_wlock", ld->name);
	wake_lock_init(&shmd->wlock, WAKE_LOCK_SUSPEND, shmd->wlock_name);
#endif

	init_completion(&ld->bcmd_cmpl);

	tasklet_init(&shmd->rx_tsk, ipc_rx_task, (unsigned long)shmd);
	INIT_DELAYED_WORK(&shmd->msg_rx_dwork, msg_rx_work);

	spin_lock_init(&shmd->tx_lock);

	ld->tx_wq = create_singlethread_workqueue("shmem_tx_wq");
	if (!ld->tx_wq) {
		gif_err("%s: ERR! fail to create tx_wq\n", ld->name);
		goto error;
	}

	INIT_DELAYED_WORK(&ld->fmt_tx_dwork, fmt_tx_work);
	ld->tx_dwork = &ld->fmt_tx_dwork;

	spin_lock_init(&shmd->tx_msq.lock);
	spin_lock_init(&shmd->rx_msq.lock);

	/* Register interrupt handlers */
	err = mbox_request_irq(MCU_GNSS, shmd->irq_gnss2ap_ipc_msg,
			       shmem_irq_msg_handler, shmd);
	if (err) {
		gif_err("%s: ERR! mbox_request_irq fail (err %d)\n",
			ld->name, err);
		goto error;
	}

	err = mbox_request_irq(MCU_GNSS, shmd->irq_gnss2ap_bcmd,
			       shmem_irq_bcmd_handler, shmd);
	if (err) {
		gif_err("%s: ERR! mbox_request_irq fail (err %d)\n",
			ld->name, err);
		goto error;
	}

	gif_debug("---\n");
	return ld;

error:
	gif_err("xxx\n");
	kfree(shmd);
	return NULL;
}
