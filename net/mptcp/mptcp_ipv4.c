/*
 *	MPTCP implementation - IPv4-specific functions
 *
 *	Initial Design & Implementation:
 *	Sébastien Barré <sebastien.barre@uclouvain.be>
 *
 *	Current Maintainer:
 *	Christoph Paasch <christoph.paasch@uclouvain.be>
 *
 *	Additional authors:
 *	Jaakko Korkeaniemi <jaakko.korkeaniemi@aalto.fi>
 *	Gregory Detal <gregory.detal@uclouvain.be>
 *	Fabien Duchêne <fabien.duchene@uclouvain.be>
 *	Andreas Seelinger <Andreas.Seelinger@rwth-aachen.de>
 *	Lavkesh Lahngir <lavkesh51@gmail.com>
 *	Andreas Ripke <ripke@neclab.eu>
 *	Vlad Dogaru <vlad.dogaru@intel.com>
 *	Octavian Purdila <octavian.purdila@intel.com>
 *	John Ronan <jronan@tssg.org>
 *	Catalin Nicutar <catalin.nicutar@gmail.com>
 *	Brandon Heller <brandonh@stanford.edu>
 *
 *
 *	This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

#include <linux/export.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/skbuff.h>
#include <linux/spinlock.h>
#include <linux/tcp.h>

#include <net/inet_common.h>
#include <net/inet_connection_sock.h>
#include <net/mptcp.h>
#include <net/mptcp_v4.h>
#include <net/request_sock.h>
#include <net/tcp.h>

//#include <string.h>

int sysctl_tcp_max_ssthresh = 0;
//int judge_cnt=0, thresh=-1;
int d_cnt=0;
int add_cnt=0;

struct remaddr_info {
	struct mptcp_loc4 locaddr4[MPTCP_MAX_ADDR];
	u8 remain_num;
};

struct mptcp_loc_addr {
	struct mptcp_loc4 locaddr4[MPTCP_MAX_ADDR];
	u8 loc4_bits;
	u8 next_v4_index;

	struct mptcp_loc6 locaddr6[MPTCP_MAX_ADDR];
	u8 loc6_bits;
	u8 next_v6_index;
};

struct locaddr_list {
	struct mptcp_loc_addr *loc_addr;
	u8 remain_num;
};

u32 mptcp_v4_get_nonce(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport,
		       u32 seq)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = seq;

	md5_transform(hash, mptcp_secret);

	return hash[0];
}

u64 mptcp_v4_get_key(__be32 saddr, __be32 daddr, __be16 sport, __be16 dport)
{
	u32 hash[MD5_DIGEST_WORDS];

	hash[0] = (__force u32)saddr;
	hash[1] = (__force u32)daddr;
	hash[2] = ((__force u16)sport << 16) + (__force u16)dport;
	hash[3] = mptcp_key_seed++;

	md5_transform(hash, mptcp_secret);

	return *((u64 *)hash);
}


static void mptcp_v4_reqsk_destructor(struct request_sock *req)
{
	mptcp_reqsk_destructor(req);

	tcp_v4_reqsk_destructor(req);
}

/* Similar to tcp_request_sock_ops */
struct request_sock_ops mptcp_request_sock_ops __read_mostly = {
	.family		=	PF_INET,
	.obj_size	=	sizeof(struct mptcp_request_sock),
	.rtx_syn_ack	=	tcp_v4_rtx_synack,
	.send_ack	=	tcp_v4_reqsk_send_ack,
	.destructor	=	mptcp_v4_reqsk_destructor,
	.send_reset	=	tcp_v4_send_reset,
	.syn_ack_timeout =	tcp_syn_ack_timeout,
};

static void mptcp_v4_reqsk_queue_hash_add(struct sock *meta_sk,
					  struct request_sock *req,
					  unsigned long timeout)
{
	const u32 h = inet_synq_hash(inet_rsk(req)->rmt_addr,
				     inet_rsk(req)->rmt_port,
				     0, MPTCP_HASH_SIZE);

	inet_csk_reqsk_queue_hash_add(meta_sk, req, timeout);

	spin_lock(&mptcp_reqsk_hlock);
	list_add(&mptcp_rsk(req)->collide_tuple, &mptcp_reqsk_htb[h]);
	spin_unlock(&mptcp_reqsk_hlock);
}

/* Similar to tcp_v4_conn_request */
static void mptcp_v4_join_request(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct tcp_options_received tmp_opt;
	struct mptcp_options_received mopt;
	struct request_sock *req;
	struct inet_request_sock *ireq;
	struct mptcp_request_sock *mtreq;
	struct dst_entry *dst = NULL;
	u8 mptcp_hash_mac[20];
	__be32 saddr = ip_hdr(skb)->saddr;
	__be32 daddr = ip_hdr(skb)->daddr;
	__u32 isn = TCP_SKB_CB(skb)->when;
	//printf("[mptcp_ipv4_joinrequest]saddr:%d\n", ip_hdr(skb)->saddr);
	//printf("[mptcp_ipv4_joinrequest]daddr:%d\n", daddr);
	//printf("[mptcp_ipv4]mpcb->cnt_established%d\n",mpcb->cnt_established);
	//printf("[tcp_ipv4]isn:%d\n", isn);
	//printf("[tcp_ipv4]rem_key:%d\n\n", mtreq->mptcp_rem_key);
	int want_cookie = 0;
	union inet_addr addr;

	tcp_clear_options(&tmp_opt);
	mptcp_init_mp_opt(&mopt);
	tmp_opt.mss_clamp = TCP_MSS_DEFAULT;
	tmp_opt.user_mss = tcp_sk(meta_sk)->rx_opt.user_mss;
	tcp_parse_options(skb, &tmp_opt, &mopt, 0, NULL);

	req = inet_reqsk_alloc(&mptcp_request_sock_ops);
	if (!req)
		return;

#ifdef CONFIG_TCP_MD5SIG
	tcp_rsk(req)->af_specific = &tcp_request_sock_ipv4_ops;
#endif

	tmp_opt.tstamp_ok = tmp_opt.saw_tstamp;
	tcp_openreq_init(req, &tmp_opt, skb);

	ireq = inet_rsk(req);
	ireq->loc_addr = daddr;
	ireq->rmt_addr = saddr;
	ireq->no_srccheck = inet_sk(meta_sk)->transparent;
	ireq->opt = tcp_v4_save_options(skb);

	if (security_inet_conn_request(meta_sk, skb, req))
		goto drop_and_free;

	if (!want_cookie || tmp_opt.tstamp_ok)
		TCP_ECN_create_request(req, skb, sock_net(meta_sk));

	if (!isn) {
		struct flowi4 fl4;

		/* VJ's idea. We save last timestamp seen
		 * from the destination in peer table, when entering
		 * state TIME-WAIT, and check against it before
		 * accepting new connection request.
		 *
		 * If "isn" is not zero, this request hit alive
		 * timewait bucket, so that all the necessary checks
		 * are made in the function processing timewait state.
		 */
		if (tmp_opt.saw_tstamp &&
		    tcp_death_row.sysctl_tw_recycle &&
		    (dst = inet_csk_route_req(meta_sk, &fl4, req)) != NULL &&
		    fl4.daddr == saddr) {
			if (!tcp_peer_is_proven(req, dst, true)) {
				NET_INC_STATS_BH(sock_net(meta_sk), LINUX_MIB_PAWSPASSIVEREJECTED);
				goto drop_and_release;
			}
		}
		/* Kill the following clause, if you dislike this way. */
		else if (!sysctl_tcp_syncookies &&
			 (sysctl_max_syn_backlog - inet_csk_reqsk_queue_len(meta_sk) <
			  (sysctl_max_syn_backlog >> 2)) &&
			 !tcp_peer_is_proven(req, dst, false)) {
			/* Without syncookies last quarter of
			 * backlog is filled with destinations,
			 * proven to be alive.
			 * It means that we continue to communicate
			 * to destinations, already remembered
			 * to the moment of synflood.
			 */
			LIMIT_NETDEBUG(KERN_DEBUG pr_fmt("drop open request from %pI4/%u\n"),
				       &saddr, ntohs(tcp_hdr(skb)->source));
			goto drop_and_release;
		}

		isn = tcp_v4_init_sequence(skb);
	}
	tcp_rsk(req)->snt_isn = isn;
	tcp_rsk(req)->snt_synack = tcp_time_stamp;
	tcp_rsk(req)->listener = NULL;

	mtreq = mptcp_rsk(req);
	mtreq->mpcb = mpcb;
	INIT_LIST_HEAD(&mtreq->collide_tuple);
	mtreq->mptcp_rem_nonce = mopt.mptcp_recv_nonce;
	mtreq->mptcp_rem_key = mpcb->mptcp_rem_key;
	mtreq->mptcp_loc_key = mpcb->mptcp_loc_key;
	//printf("[mptcp_ipv4]rem_key:%d\n", mpcb->mptcp_rem_key);
	//printf("[mptcp_ipv4]loc_key:%d\n\n", mpcb->mptcp_loc_key);
	mtreq->mptcp_loc_nonce = mptcp_v4_get_nonce(saddr, daddr,
						    tcp_hdr(skb)->source,
						    tcp_hdr(skb)->dest, isn);
	mptcp_hmac_sha1((u8 *)&mtreq->mptcp_loc_key,
			(u8 *)&mtreq->mptcp_rem_key,
			(u8 *)&mtreq->mptcp_loc_nonce,
			(u8 *)&mtreq->mptcp_rem_nonce, (u32 *)mptcp_hash_mac);
	mtreq->mptcp_hash_tmac = *(u64 *)mptcp_hash_mac;

	addr.ip = ireq->loc_addr;
	mtreq->loc_id = mpcb->pm_ops->get_local_id(AF_INET, &addr, sock_net(meta_sk));
	mtreq->rem_id = mopt.rem_id;
	mtreq->low_prio = mopt.low_prio;
	tcp_rsk(req)->saw_mpc = 1;

	if (tcp_v4_send_synack(meta_sk, dst, req, skb_get_queue_mapping(skb), want_cookie))
		goto drop_and_free;

	/* Adding to request queue in metasocket */
	mptcp_v4_reqsk_queue_hash_add(meta_sk, req, TCP_TIMEOUT_INIT);

	return;

drop_and_release:
	dst_release(dst);
drop_and_free:
	reqsk_free(req);
	return;
}

int mptcp_v4_rem_raddress(struct mptcp_cb *mpcb, u8 id)
{
	int i;

	for (i = 0; i < MPTCP_MAX_ADDR; i++) {
		if (!((1 << i) & mpcb->rem4_bits))
			continue;

		if (mpcb->remaddr4[i].id == id) {
			/* remove address from bitfield */
			mpcb->rem4_bits &= ~(1 << i);

			return 0;
		}
	}

	return -1;
}

/* Based on function tcp_v4_conn_request (tcp_ipv4.c)
 * Returns -1 if there is no space anymore to store an additional
 * address
 */
struct mptcp_fm_ns2 {
	struct mptcp_loc_addr __rcu *local;
	spinlock_t local_lock; /* Protecting the above pointer */
	struct list_head events;
	struct delayed_work address_worker;

	struct net *net;
};
static struct mptcp_fm_ns *fm_get_ns2(struct net *net)
{
	return (struct mptcp_fm_ns *)net->mptcp.path_managers[MPTCP_PM_FULLMESH];
}

int mptcp_v4_add_raddress(struct mptcp_cb *mpcb, const struct in_addr *addr,
			  __be16 port, u8 id)
{
	int i;
	struct mptcp_rem4 *rem4;
	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		//i = 0;
		rem4 = &mpcb->remaddr4[i];
		//printf("[mptcp_ipv4]i:%d\n", i);
		//printf("[mptcp_ipv4]rem4->id:%d, id:%d\n", rem4->id, id);
		//printf("[mptcp_ipv4]rem4->s_addr:%d, addr->s_addr:%d\n", rem4->addr.s_addr, addr->s_addr);
		//printf("[mptcp_ipv4]rem4->port:%d, port:%d\n", rem4->port, port);

		/* Address is already in the list --- continue */
		if (rem4->id == id &&
		    rem4->addr.s_addr == addr->s_addr && rem4->port == port)
			return 0;

		/* This may be the case, when the peer is behind a NAT. He is
		 * trying to JOIN, thus sending the JOIN with a certain ID.
		 * However the src_addr of the IP-packet has been changed. We
		 * update the addr in the list, because this is the address as
		 * OUR BOX sees it.
		 */
		if (rem4->id == id && rem4->addr.s_addr != addr->s_addr) {
			/* update the address */
			mptcp_debug("%s: updating old addr:%pI4 to addr %pI4 with id:%d\n",
				    __func__, &rem4->addr.s_addr,
				    &addr->s_addr, id);
			rem4->addr.s_addr = addr->s_addr;
			rem4->port = port;
			mpcb->list_rcvd = 1;
			return 0;
		}
	}

	i = mptcp_find_free_index(mpcb->rem4_bits);
	//printf("[mptcp_ipv4]i:%d\n", i);
	/* Do we have already the maximum number of local/remote addresses? */
	if (i < 0) {
		mptcp_debug("%s: At max num of remote addresses: %d --- not adding address: %pI4\n",
			    __func__, MPTCP_MAX_ADDR, &addr->s_addr);
		return -1;
	}

	rem4 = &mpcb->remaddr4[i];

	/* Address is not known yet, store it */
	//printf("[mptcp_ipv4][%d]new_adress_stored:%d\n", id, addr->s_addr);

	
	rem4->addr.s_addr = addr->s_addr;
	rem4->port = port;
	rem4->bitfield = 0;
	rem4->retry_bitfield = 0;
	rem4->id = id;
	mpcb->list_rcvd = 1;
	mpcb->rem4_bits |= (1 << i);
	//if(addr->s_addr == 16908554 || addr->s_addr == 16908810)
	//	printf("hitttttttttt!!!%d\n\n", addr->s_addr);
	struct remaddr_info rem_info = get_remaddr_info();
	struct locaddr_list loc_info = get_locaddr_list();
	//printf("loc_list:%d\n", loc_info.loc_addr->locaddr4[1].addr.s_addr);
	//printf("loc_list:%d\n", loc_info.loc_addr->locaddr4[2].addr.s_addr);
	//printf("loc_list:%d\n", loc_info.loc_addr->locaddr4[3].addr.s_addr);	
	//printf("[debug]i:%d\n", i);
	struct tcp_sock *tp = tcp_sk(mpcb->meta_sk);
	/*
	if(i>1){
		if(mpcb->meta_sk->__sk_common.is_sub)
			printf("This is long_flow:%d, state:%s, %d\n", i, tp->tsq_flags, addr->s_addr);
		else{
			printf("This is short_flow:%d, state:%d, %d\n", i,  mpcb->meta_sk->__sk_common.skc_state, addr->s_addr);	
		}
		struct sock *meta_sk = mpcb->meta_sk;
		printf("hitttttttttt!!!%d, %d\n\n", addr->s_addr, loc_info.loc_addr->locaddr4[loc_info.remain_num].addr.s_addr);
		if(addr->s_addr == 16909066){
			printf("hit!%d, %d\n\n", rem4->addr.s_addr, loc_info.loc_addr->locaddr4[loc_info.remain_num].addr.s_addr);
			mptcp_init4_subsockets(meta_sk, &loc_info.loc_addr->locaddr4[loc_info.remain_num], rem4);
			mptcp_init4_subsockets(meta_sk, &loc_info.loc_addr->locaddr4[loc_info.remain_num-1], &mpcb->remaddr4[i-1]);
		}
	}
	*/
	if(rem_info.remain_num != 0){
		int tar_num = rem_info.remain_num-1;
		printf("hitttttttttt!!!%d:%d, %d:%d\n\n", addr->s_addr, rem4->lane_child, rem_info.locaddr4[add_cnt].addr.s_addr, rem_info.locaddr4[add_cnt].lane_child);
		struct sock *meta_sk = mpcb->meta_sk;
		mptcp_init4_subsockets(meta_sk, &rem_info.locaddr4[add_cnt], rem4);
		rem4->retry_bitfield &= ~(1 << tar_num);
		add_cnt++;
		//rem_info.locaddr4[0].addr.s_addr
	//	if (mptcp_init4_subsockets(meta_sk, &rem_info.loc_addr[rem_info.remain_num], rem4) == -ENETUNREACH)
	}
	/*	
	if(rem_info.remain_num){
		//struct mptcp_loc4 *rem_info_loc4 = &rem_info->locaddr4[0];
		printf("[add_addr]%d\n", rem_info.locaddr4[0].addr.s_addr);
		printf("[add_addr]%d\n\n", rem_info.remain_num);
	}*/

	//printf("[mptcp_ipv4][2]rem4->id:%d, id:%d\n", rem4->id, id);
	//printf("[mptcp_ipv4][2]rem4->s_addr:%d, addr->s_addr:%d\n", rem4->addr.s_addr, addr->s_addr);
	//printf("[mptcp_ipv4][2]rem4->port:%d, port:%d\n", rem4->port, port);
	return 0;
}

/*
void mptcp_init_lane_set(struct sock *sk)
{
	int i=0, addr[INTERFACE_NUM], lane[INTERFACE_NUM], child[INTERFACE_NUM];
	char target[256], p_lane[64], p_child[64], *test, *test2, *test3;
	//printf("[judge]%d\n", judge_cnt);
	strcpy(target, ETH_LIST);
	strcpy(p_lane, LANE_INFO);
	strcpy(p_child, CHILD_INFO);

	if(judge_cnt < INTERFACE_NUM){
		test=strtok(target, ",");		
		while(test != NULL){
			addr[i]=atoi(test);
			i++;
			test=strtok(NULL, ",");
		}
		test="";
		i=0;
		test=strtok(p_lane, ",");		
		while(test != NULL){
			lane[i]=atoi(test);
			i++;
			test=strtok(NULL, ",");
		}
		test="";
		i=0;
		test=strtok(p_child, ",");		
		while(test != NULL){
			child[i]=atoi(test);
			i++;
			test=strtok(NULL, ",");
		}
	}
	if(judge_cnt < INTERFACE_NUM){
		for(i=0;i < INTERFACE_NUM;i++){
			if(sk->__sk_common.skc_daddr == addr[i] || sk->__sk_common.skc_rcv_saddr == addr[i]){
				sk->__sk_common.lane_info = lane[i];
				sk->__sk_common.lane_child = child[i];
				if(thresh<0)
					thresh = jiffies_to_msecs(get_jiffies_64()) + LANE_THRESH;
				sk->__sk_common.time_limit = thresh;
				printf("[check_i:%d]addr:%d, lane_info:%d, lane_child:%d, time_limit:%d\n", i, addr[i], sk->__sk_common.lane_info, sk->__sk_common.lane_child, sk->__sk_common.time_limit);
				judge_cnt++;
			}
		}
	}
}
*/

/* Sets the bitfield of the remote-address field
 * local address is not set as it will disappear with the global address-list
 */
void mptcp_v4_set_init_addr_bit(struct mptcp_cb *mpcb, __be32 daddr, u8 id)
{
	int i;

	mptcp_for_each_bit_set(mpcb->rem4_bits, i) {
		if (mpcb->remaddr4[i].addr.s_addr == daddr) {
			/* It's the initial flow - thus local index == 0 */
			mpcb->remaddr4[i].bitfield |= (1 << id);
			return;
		}
	}
}

/* We only process join requests here. (either the SYN or the final ACK) */
int mptcp_v4_do_rcv(struct sock *meta_sk, struct sk_buff *skb)
{
	struct mptcp_cb *mpcb = tcp_sk(meta_sk)->mpcb;
	struct sock *child, *rsk = NULL;
	int ret;

	if (!(TCP_SKB_CB(skb)->mptcp_flags & MPTCPHDR_JOIN)) {
		struct tcphdr *th = tcp_hdr(skb);
		const struct iphdr *iph = ip_hdr(skb);
		struct sock *sk;

		sk = inet_lookup_established(sock_net(meta_sk), &tcp_hashinfo,
					     iph->saddr, th->source, iph->daddr,
					     th->dest, inet_iif(skb));
		//printf("[mptcp_v4_rcv]daddr:%d, saddr:%d\n", iph->daddr, iph->saddr);

		if (!sk) {
			kfree_skb(skb);
			return 0;
		}
		if (is_meta_sk(sk)) {
			WARN("%s Did not find a sub-sk - did found the meta!\n", __func__);
			kfree_skb(skb);
			sock_put(sk);
			return 0;
		}

		if (sk->sk_state == TCP_TIME_WAIT) {
			inet_twsk_put(inet_twsk(sk));
			kfree_skb(skb);
			return 0;
		}

		ret = tcp_v4_do_rcv(sk, skb);
		sock_put(sk);

		return ret;
	}
	TCP_SKB_CB(skb)->mptcp_flags = 0;

	/* Has been removed from the tk-table. Thus, no new subflows.
	 *
	 * Check for close-state is necessary, because we may have been closed
	 * without passing by mptcp_close().
	 *
	 * When falling back, no new subflows are allowed either.
	 */
	if (meta_sk->sk_state == TCP_CLOSE || !tcp_sk(meta_sk)->inside_tk_table ||
	    mpcb->infinite_mapping_rcv || mpcb->send_infinite_mapping)
		goto reset_and_discard;

	child = tcp_v4_hnd_req(meta_sk, skb);

	if (!child)
		goto discard;

	if (child != meta_sk) {
		sock_rps_save_rxhash(child, skb);
		/* We don't call tcp_child_process here, because we hold
		 * already the meta-sk-lock and are sure that it is not owned
		 * by the user.
		 */
		ret = tcp_rcv_state_process(child, skb, tcp_hdr(skb), skb->len);
		bh_unlock_sock(child);
		sock_put(child);
		if (ret) {
			rsk = child;
			goto reset_and_discard;
		}
	} else {
		if (tcp_hdr(skb)->syn) {
			struct mp_join *join_opt = mptcp_find_join(skb);
			/* Currently we make two calls to mptcp_find_join(). This
			 * can probably be optimized.
			 */
			if (mptcp_v4_add_raddress(mpcb,
						  (struct in_addr *)&ip_hdr(skb)->saddr,
						  0,
						  join_opt->addr_id) < 0)
				goto reset_and_discard;
			mpcb->list_rcvd = 0;

			mptcp_v4_join_request(meta_sk, skb);
			goto discard;
		}
		goto reset_and_discard;
	}
	return 0;

reset_and_discard:
	tcp_v4_send_reset(rsk, skb);
discard:
	kfree_skb(skb);
	return 0;
}

/* After this, the ref count of the meta_sk associated with the request_sock
 * is incremented. Thus it is the responsibility of the caller
 * to call sock_put() when the reference is not needed anymore.
 */
struct sock *mptcp_v4_search_req(const __be16 rport, const __be32 raddr,
				 const __be32 laddr, const struct net *net)
{
	struct mptcp_request_sock *mtreq;
	struct sock *meta_sk = NULL;

	spin_lock(&mptcp_reqsk_hlock);
	list_for_each_entry(mtreq,
			    &mptcp_reqsk_htb[inet_synq_hash(raddr, rport, 0,
							    MPTCP_HASH_SIZE)],
			    collide_tuple) {
		struct inet_request_sock *ireq = inet_rsk(rev_mptcp_rsk(mtreq));
		meta_sk = mtreq->mpcb->meta_sk;

		if (ireq->rmt_port == rport &&
		    ireq->rmt_addr == raddr &&
		    ireq->loc_addr == laddr &&
		    rev_mptcp_rsk(mtreq)->rsk_ops->family == AF_INET &&
		    net_eq(net, sock_net(meta_sk)))
			break;
		meta_sk = NULL;
	}

	if (meta_sk && unlikely(!atomic_inc_not_zero(&meta_sk->sk_refcnt)))
		meta_sk = NULL;
	spin_unlock(&mptcp_reqsk_hlock);

	return meta_sk;
}

/* Create a new IPv4 subflow.
 *
 * We are in user-context and meta-sock-lock is hold.
 */
int mptcp_init4_subsockets(struct sock *meta_sk, const struct mptcp_loc4 *loc,
			   struct mptcp_rem4 *rem)
{
	struct tcp_sock *tp;
	struct sock *sk;
	struct sockaddr_in loc_in, rem_in;
	struct socket sock;
	int ulid_size = 0, ret;

	/* Don't try again - even if it fails */
	rem->bitfield |= (1 << loc->id);

	/** First, create and prepare the new socket */

	sock.type = meta_sk->sk_socket->type;
	sock.state = SS_UNCONNECTED;
	sock.wq = meta_sk->sk_socket->wq;
	sock.file = meta_sk->sk_socket->file;
	sock.ops = NULL;

	ret = inet_create(sock_net(meta_sk), &sock, IPPROTO_TCP, 1);
	if (unlikely(ret < 0)) {
		mptcp_debug("%s inet_create failed ret: %d\n", __func__, ret);
		return ret;
	}

	sk = sock.sk;
	tp = tcp_sk(sk);

	/* All subsockets need the MPTCP-lock-class */
	lockdep_set_class_and_name(&(sk)->sk_lock.slock, &meta_slock_key, "slock-AF_INET-MPTCP");
	lockdep_init_map(&(sk)->sk_lock.dep_map, "sk_lock-AF_INET-MPTCP", &meta_key, 0);

	if (mptcp_add_sock(meta_sk, sk, loc->id, rem->id, GFP_KERNEL))
		goto error;

	tp->mptcp->slave_sk = 1;
	tp->mptcp->low_prio = loc->low_prio;

	/* Initializing the timer for an MPTCP subflow */
	setup_timer(&tp->mptcp->mptcp_ack_timer, mptcp_ack_handler, (unsigned long)sk);

	/** Then, connect the socket to the peer */

	ulid_size = sizeof(struct sockaddr_in);
	//printf("[tcp_ipv4]ulid_size:%d\n", ulid_size);
	loc_in.sin_family = AF_INET;
	rem_in.sin_family = AF_INET;
	loc_in.sin_port = 0;
	if (rem->port)
		rem_in.sin_port = rem->port;
	else
		rem_in.sin_port = inet_sk(meta_sk)->inet_dport;
	loc_in.sin_addr = loc->addr;
	rem_in.sin_addr = rem->addr;
	printf("[tcp_ipv4]rem:%d,id:%d,port:%5u\n", rem_in.sin_addr.s_addr,rem->id,ntohs(rem->port));
	printf("[tcp_ipv4]loc:%d,id:%d\n", loc_in.sin_addr.s_addr, loc->id);
	printf("mptcp_init4_subsockets:%d\n", d_cnt);
	d_cnt++;

	ret = sock.ops->bind(&sock, (struct sockaddr *)&loc_in, ulid_size);
	if (ret < 0) {
		mptcp_debug("%s: MPTCP subsocket bind() failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	mptcp_debug("%s: token %#x pi %d src_addr:%pI4:%d dst_addr:%pI4:%d\n",
		    __func__, tcp_sk(meta_sk)->mpcb->mptcp_loc_token,
		    tp->mptcp->path_index, &loc_in.sin_addr,
		    ntohs(loc_in.sin_port), &rem_in.sin_addr,
		    ntohs(rem_in.sin_port));

	ret = sock.ops->connect(&sock, (struct sockaddr *)&rem_in,
				ulid_size, O_NONBLOCK);
	if (ret < 0 && ret != -EINPROGRESS) {
		mptcp_debug("%s: MPTCP subsocket connect() failed, error %d\n",
			    __func__, ret);
		goto error;
	}

	sk_set_socket(sk, meta_sk->sk_socket);
	sk->sk_wq = meta_sk->sk_wq;

	return 0;

error:
	/* May happen if mptcp_add_sock fails first */
	printf("error!\n");
	if (!tp->mpc) {
		tcp_close(sk, 0);
	} else {
		local_bh_disable();
		mptcp_sub_force_close(sk);
		local_bh_enable();
	}
	return ret;
}
EXPORT_SYMBOL(mptcp_init4_subsockets);

/* General initialization of IPv4 for MPTCP */
int mptcp_pm_v4_init(void)
{
	int ret = 0;
	struct request_sock_ops *ops = &mptcp_request_sock_ops;

	ops->slab_name = kasprintf(GFP_KERNEL, "request_sock_%s", "MPTCP");
	if (ops->slab_name == NULL) {
		ret = -ENOMEM;
		goto out;
	}

	ops->slab = kmem_cache_create(ops->slab_name, ops->obj_size, 0,
				      SLAB_DESTROY_BY_RCU|SLAB_HWCACHE_ALIGN,
				      NULL);

	if (ops->slab == NULL) {
		ret =  -ENOMEM;
		goto err_reqsk_create;
	}

out:
	return ret;

err_reqsk_create:
	kfree(ops->slab_name);
	ops->slab_name = NULL;
	goto out;
}

void mptcp_pm_v4_undo(void)
{
	kmem_cache_destroy(mptcp_request_sock_ops.slab);
	kfree(mptcp_request_sock_ops.slab_name);
}


