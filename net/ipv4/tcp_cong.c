/*
 * Plugable TCP congestion control support and newReno
 * congestion control.
 * Based on ideas from I/O scheduler support and Web100.
 *
 * Copyright (C) 2005 Stephen Hemminger <shemminger@osdl.org>
 */

#define pr_fmt(fmt) "TCP: " fmt

#include <linux/module.h>
#include <linux/mm.h>
#include <linux/types.h>
#include <linux/list.h>
#include <linux/gfp.h>
#include <net/tcp.h>
#include <net/mptcp.h>
//#include <string.h>

//int sysctl_tcp_max_ssthresh = 0;

int base_rtt=0;
struct work_struct *work_save[INTERFACE_NUM], *last_work;
int work_cnt=0, queue_cnt=0;

/* 0->complete_pair, 1->mptcp_simple_lane, 2->mptcp_cost */
//int config_mptcp_plug=MPTCP_PLUGIN_CONFIG;
int mptcp_plugin_config=0;

static DEFINE_SPINLOCK(tcp_cong_list_lock);
static LIST_HEAD(tcp_cong_list);

/* Simple linear search, don't expect many entries! */
static struct tcp_congestion_ops *tcp_ca_find(const char *name)
{
	struct tcp_congestion_ops *e;

	list_for_each_entry_rcu(e, &tcp_cong_list, list) {
		if (strcmp(e->name, name) == 0)
			return e;
	}

	return NULL;
}

/*
 * Attach new congestion control algorithm to the list
 * of available options.
 */
int tcp_register_congestion_control(struct tcp_congestion_ops *ca)
{
	int ret = 0;

	/* all algorithms must implement ssthresh and cong_avoid ops */
	if (!ca->ssthresh || !ca->cong_avoid) {
		pr_err("%s does not implement required ops\n", ca->name);
		return -EINVAL;
	}

	spin_lock(&tcp_cong_list_lock);
	if (tcp_ca_find(ca->name)) {
		pr_notice("%s already registered\n", ca->name);
		ret = -EEXIST;
	} else {
		list_add_tail_rcu(&ca->list, &tcp_cong_list);
		pr_info("%s registered\n", ca->name);
	}
	spin_unlock(&tcp_cong_list_lock);

	return ret;
}
EXPORT_SYMBOL_GPL(tcp_register_congestion_control);

/*
 * Remove congestion control algorithm, called from
 * the module's remove function.  Module ref counts are used
 * to ensure that this can't be done till all sockets using
 * that method are closed.
 */
void tcp_unregister_congestion_control(struct tcp_congestion_ops *ca)
{
	spin_lock(&tcp_cong_list_lock);
	list_del_rcu(&ca->list);
	spin_unlock(&tcp_cong_list_lock);
}
EXPORT_SYMBOL_GPL(tcp_unregister_congestion_control);

/* Assign choice of congestion control. */
void tcp_init_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_congestion_ops *ca;
	struct sock_common *sk_c;

	/* proposal mptcp_lane*/
	//tcp_init_lane_set(sk);

	/* if no choice made yet assign the current value set as default */
	if (icsk->icsk_ca_ops == &tcp_init_congestion_ops) {
		rcu_read_lock();
		list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
			if (try_module_get(ca->owner)) {
				icsk->icsk_ca_ops = ca;
				break;
			}

			/* fallback to next available */
		}
		rcu_read_unlock();
	}

	if (icsk->icsk_ca_ops->init)
		icsk->icsk_ca_ops->init(sk);
}

/* Manage refcounts on socket close. */
void tcp_cleanup_congestion_control(struct sock *sk)
{
	struct inet_connection_sock *icsk = inet_csk(sk);

	if (icsk->icsk_ca_ops->release)
		icsk->icsk_ca_ops->release(sk);
	module_put(icsk->icsk_ca_ops->owner);
}

/* Used by sysctl to change default congestion control */
int tcp_set_default_congestion_control(const char *name)
{
	struct tcp_congestion_ops *ca;
	int ret = -ENOENT;

	spin_lock(&tcp_cong_list_lock);
	ca = tcp_ca_find(name);
#ifdef CONFIG_MODULES
	if (!ca && capable(CAP_NET_ADMIN)) {
		spin_unlock(&tcp_cong_list_lock);

		request_module("tcp_%s", name);
		spin_lock(&tcp_cong_list_lock);
		ca = tcp_ca_find(name);
	}
#endif

	if (ca) {
		ca->flags |= TCP_CONG_NON_RESTRICTED;	/* default is always allowed */
		list_move(&ca->list, &tcp_cong_list);
		ret = 0;
	}
	spin_unlock(&tcp_cong_list_lock);

	return ret;
}

/* Set default value from kernel configuration at bootup */
static int __init tcp_congestion_default(void)
{
	return tcp_set_default_congestion_control(CONFIG_DEFAULT_TCP_CONG);
}
late_initcall(tcp_congestion_default);


/* Build string with list of available congestion control values */
void tcp_get_available_congestion_control(char *buf, size_t maxlen)
{
	struct tcp_congestion_ops *ca;
	size_t offs = 0;

	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Get current default congestion control */
void tcp_get_default_congestion_control(char *name)
{
	struct tcp_congestion_ops *ca;
	/* We will always have reno... */
	BUG_ON(list_empty(&tcp_cong_list));

	rcu_read_lock();
	ca = list_entry(tcp_cong_list.next, struct tcp_congestion_ops, list);
	strncpy(name, ca->name, TCP_CA_NAME_MAX);
	rcu_read_unlock();
}

/* Built list of non-restricted congestion control values */
void tcp_get_allowed_congestion_control(char *buf, size_t maxlen)
{
	struct tcp_congestion_ops *ca;
	size_t offs = 0;

	*buf = '\0';
	rcu_read_lock();
	list_for_each_entry_rcu(ca, &tcp_cong_list, list) {
		if (!(ca->flags & TCP_CONG_NON_RESTRICTED))
			continue;
		offs += snprintf(buf + offs, maxlen - offs,
				 "%s%s",
				 offs == 0 ? "" : " ", ca->name);

	}
	rcu_read_unlock();
}

/* Change list of non-restricted congestion control */
int tcp_set_allowed_congestion_control(char *val)
{
	struct tcp_congestion_ops *ca;
	char *saved_clone, *clone, *name;
	int ret = 0;

	saved_clone = clone = kstrdup(val, GFP_USER);
	if (!clone)
		return -ENOMEM;

	spin_lock(&tcp_cong_list_lock);
	/* pass 1 check for bad entries */
	while ((name = strsep(&clone, " ")) && *name) {
		ca = tcp_ca_find(name);
		if (!ca) {
			ret = -ENOENT;
			goto out;
		}
	}

	/* pass 2 clear old values */
	list_for_each_entry_rcu(ca, &tcp_cong_list, list)
		ca->flags &= ~TCP_CONG_NON_RESTRICTED;

	/* pass 3 mark as allowed */
	while ((name = strsep(&val, " ")) && *name) {
		ca = tcp_ca_find(name);
		WARN_ON(!ca);
		if (ca)
			ca->flags |= TCP_CONG_NON_RESTRICTED;
	}
out:
	spin_unlock(&tcp_cong_list_lock);
	kfree(saved_clone);

	return ret;
}


/* Change congestion control for socket */
int tcp_set_congestion_control(struct sock *sk, const char *name)
{
	struct inet_connection_sock *icsk = inet_csk(sk);
	struct tcp_congestion_ops *ca;
	int err = 0;

	rcu_read_lock();
	ca = tcp_ca_find(name);

	/* no change asking for existing value */
	if (ca == icsk->icsk_ca_ops)
		goto out;

#ifdef CONFIG_MODULES
	/* not found attempt to autoload module */
	if (!ca && capable(CAP_NET_ADMIN)) {
		rcu_read_unlock();
		request_module("tcp_%s", name);
		rcu_read_lock();
		ca = tcp_ca_find(name);
	}
#endif
	if (!ca)
		err = -ENOENT;

	else if (!((ca->flags & TCP_CONG_NON_RESTRICTED) ||
		   ns_capable(sock_net(sk)->user_ns, CAP_NET_ADMIN)))
		err = -EPERM;

	else if (!try_module_get(ca->owner))
		err = -EBUSY;

	else {
		tcp_cleanup_congestion_control(sk);
		icsk->icsk_ca_ops = ca;

		if (sk->sk_state != TCP_CLOSE && icsk->icsk_ca_ops->init)
			icsk->icsk_ca_ops->init(sk);
	}
 out:
	rcu_read_unlock();
	return err;
}

/* RFC2861 Check whether we are limited by application or congestion window
 * This is the inverse of cwnd check in tcp_tso_should_defer
 */
bool tcp_is_cwnd_limited(const struct sock *sk, u32 in_flight)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	u32 left;

	if (in_flight >= tp->snd_cwnd)
		return true;

	left = tp->snd_cwnd - in_flight;
	if (sk_can_gso(sk) &&
	    left * sysctl_tcp_tso_win_divisor < tp->snd_cwnd &&
	    left * tp->mss_cache < sk->sk_gso_max_size &&
	    left < sk->sk_gso_max_segs)
		return true;
	return left <= tcp_max_tso_deferred_mss(tp);
}
EXPORT_SYMBOL_GPL(tcp_is_cwnd_limited);

/*
 * Slow start is used when congestion window is less than slow start
 * threshold. This version implements the basic RFC2581 version
 * and optionally supports:
 * 	RFC3742 Limited Slow Start  	  - growth limited to max_ssthresh
 *	RFC3465 Appropriate Byte Counting - growth limited by bytes acknowledged
 */
void tcp_slow_start(struct tcp_sock *tp)
{
	int cnt; /* increase in packets */
	unsigned int delta = 0;
	u32 snd_cwnd = tp->snd_cwnd;
	//printf("slow_start\n");
	//printf("slow_start:%d, lane:%d\n", tp->inet_conn.icsk_inet.sk.__sk_common.skc_daddr, tp->inet_conn.icsk_inet.sk.__sk_common.lane_info);
	//printf("now:%d\n",jiffies_to_msecs(tcp_time_stamp)>>3);
	//printf("now:%d\n", jiffies_to_msecs(get_jiffies_64()));

	if (unlikely(!snd_cwnd)) {
		pr_err_once("snd_cwnd is nul, please report this bug.\n");
		snd_cwnd = 1U;
	}

	if (sysctl_tcp_max_ssthresh > 0 && tp->snd_cwnd > sysctl_tcp_max_ssthresh)
		cnt = sysctl_tcp_max_ssthresh >> 1;	/* limited slow start */
	else
		cnt = snd_cwnd;				/* exponential increase */

	tp->snd_cwnd_cnt += cnt;
	while (tp->snd_cwnd_cnt >= snd_cwnd) {
		tp->snd_cwnd_cnt -= snd_cwnd;
		delta++;
	}
	tp->snd_cwnd = min(snd_cwnd + delta, tp->snd_cwnd_clamp);
}
EXPORT_SYMBOL_GPL(tcp_slow_start);

/* In theory this is tp->snd_cwnd += 1 / tp->snd_cwnd (or alternative w) */
void tcp_cong_avoid_ai(struct tcp_sock *tp, u32 w)
{
	if (tp->snd_cwnd_cnt >= w) {
		if (tp->snd_cwnd < tp->snd_cwnd_clamp)
			tp->snd_cwnd++;
		tp->snd_cwnd_cnt = 0;
	} else {
		tp->snd_cwnd_cnt++;
	}
}
EXPORT_SYMBOL_GPL(tcp_cong_avoid_ai);

void mptcp_task_save(struct work_struct *work)
{
	if(work_cnt==0 || last_work != work){
		work_save[work_cnt] = work;
		last_work = work;
		work_cnt++;
		queue_cnt++;
	}
}

void mptcp_task_queue()
{
	//printf("test:::::::::::::::::::::::::%d\n\n\n", work_cnt);
	create_subflow_worker2(work_save[0]);
	queue_cnt--;
}

void mptcp_cost_calc(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	int i=0, j, nu_rtt=0, cost=0, thre_cost=0;
	int alpha=1;
	int beta=1;
	int delta=1;
	int gamma=10;
	/* updating base_rtt */
	if(sk->__sk_common.base_rtt == 0 ||sk->__sk_common.base_rtt > tp->srtt){
		sk->__sk_common.base_rtt=tp->srtt;
	}
	/* calcurating_cost */
	nu_rtt = tp->srtt - sk->__sk_common.base_rtt;
	for(j=1; j<beta; j++){
		nu_rtt = nu_rtt * nu_rtt;
	}
	if(sk->__sk_common.lane_info == 0){
		thre_cost=tcp_time_stamp - sk->__sk_common.time_limit_stamp;
		for(j=1; j<delta; j++){
			thre_cost = thre_cost * thre_cost;
		}
	}else{
		thre_cost=0;
	}
	cost = alpha * nu_rtt + delta * thre_cost;
	//printf("[debug]cost:%d, ", cost);
	if (sk->__sk_common.base_cost == 0 || cost < sk->__sk_common.base_cost){
		if(cost < 0)
			cost = alpha * nu_rtt;
		sk->__sk_common.base_cost = cost;
	}
	if (sk->__sk_common.base_cost == 0)
		sk->__sk_common.base_cost = 100;
	sk->__sk_common.path_cost = sk->__sk_common.base_cost * (1 + alpha * nu_rtt) + gamma * thre_cost;
	
	//printf("now:%d, now2:%d\n", tcp_time_stamp, jiffies_to_msecs(get_jiffies_64()));
	
	/* judging phase */
	int tmp=0, lane_tmp=-1;
	mptcp_for_each_sk(mpcb, sub_sk) {
		struct tcp_sock *sub_tp = tcp_sk(sub_sk);
		if(sub_sk->__sk_common.base_rtt != 0){
			if(tmp == 0){
				tmp = sub_sk->__sk_common.path_cost;
				lane_tmp = sub_sk->__sk_common.lane_info;
			}
			if(tmp > sub_sk->__sk_common.path_cost){
				tmp = sub_sk->__sk_common.path_cost;
				lane_tmp = sub_sk->__sk_common.lane_info;
			}
		}
		printf("[tcp_reno_cong_avod:i%d::%d]dst:%d, snd:%d, cost:%d, base_cost:%d srtt:%d, base_rtt:%d, cwnd:%d\n", i, sub_sk->__sk_common.lane_info, sub_sk->__sk_common.skc_daddr, sub_sk->__sk_common.skc_rcv_saddr, sub_sk->__sk_common.path_cost, sub_sk->__sk_common.base_cost, sub_tp->srtt, sub_sk->__sk_common.base_rtt, sub_tp->snd_cwnd);
		i++;
	}
	printf("\n");
	if(lane_tmp == 1 && sk->__sk_common.is_path != 1){
		printf("change!!!!!!!!!!!!\n\n\n\n");
		mptcp_for_each_sk(mpcb, sub_sk) {
			sub_sk->__sk_common.is_path=1;
			if(sub_sk->__sk_common.lane_info == 1){
				sub_sk->__sk_common.path_state = 1;
			}else{
				//printf("[debug]daddr:%d, %d\n", sub_sk->__sk_common.skc_daddr, sub_sk->__sk_common.lane_info);
				sub_sk->__sk_common.path_state = 0;
			}
		}
		printf("[cost_calc]lane:%d, is_path:%d, %d, %d\n", sk->__sk_common.lane_info, sk->__sk_common.is_path, sk->__sk_common.skc_daddr, sk->__sk_common.skc_rcv_saddr);
	}
}

void mptcp_judge_limit(struct sock *sk)
{
	struct tcp_sock *tp = tcp_sk(sk);
	struct mptcp_cb *mpcb = tcp_sk(sk)->mpcb;
	struct sock *sub_sk;
	if (sk->__sk_common.lane_info == 0 || sk->__sk_common.is_path == 1){
		if(sk->__sk_common.time_limit < jiffies_to_msecs(get_jiffies_64())){
			mptcp_for_each_sk(mpcb, sub_sk) {
				sub_sk->__sk_common.is_path = 1;
				if(sub_sk->__sk_common.lane_info){
					sub_sk->__sk_common.path_state = 1;
				}else{
					sub_sk->__sk_common.path_state = 0;
				}					
			}
		}
	}
}
/*
 * TCP Reno congestion control
 * This is special case used for fallback as well.
 */
/* This is Jacobson's slow start and congestion avoidance.
 * SIGCOMM '88, p. 328.
 */
void tcp_reno_cong_avoid(struct sock *sk, u32 ack, u32 in_flight)
{
	struct tcp_sock *tp = tcp_sk(sk);
	/* mptcp_mode config.
	 * 0->complete_pair, 1->mptcp_simple_lane, 2->mptcp_cost */
	if(mptcp_plugin_config == 1){
		mptcp_judge_limit(sk);
	}else if(mptcp_plugin_config == 2){
		mptcp_cost_calc(sk);
	}

	if (!tcp_is_cwnd_limited(sk, in_flight)){
		return;
	}
	/* In "safe" area, increase. */
	if (tp->snd_cwnd <= tp->snd_ssthresh){
		tcp_slow_start(tp);
	}
	/* In dangerous area, increase slowly. */
	else{
		tcp_cong_avoid_ai(tp, tp->snd_cwnd);
	}
}
EXPORT_SYMBOL_GPL(tcp_reno_cong_avoid);

/* Slow start threshold is half the congestion window (min 2) */
u32 tcp_reno_ssthresh(struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return max(tp->snd_cwnd >> 1U, 2U);
}
EXPORT_SYMBOL_GPL(tcp_reno_ssthresh);

/* Lower bound on congestion window with halving. */
u32 tcp_reno_min_cwnd(const struct sock *sk)
{
	const struct tcp_sock *tp = tcp_sk(sk);
	return tp->snd_ssthresh/2;
}
EXPORT_SYMBOL_GPL(tcp_reno_min_cwnd);

struct tcp_congestion_ops tcp_reno = {
	.flags		= TCP_CONG_NON_RESTRICTED,
	.name		= "reno",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,
};

/* Initial congestion control used (until SYN)
 * really reno under another name so we can tell difference
 * during tcp_set_default_congestion_control
 */
struct tcp_congestion_ops tcp_init_congestion_ops  = {
	.name		= "",
	.owner		= THIS_MODULE,
	.ssthresh	= tcp_reno_ssthresh,
	.cong_avoid	= tcp_reno_cong_avoid,
	.min_cwnd	= tcp_reno_min_cwnd,
};
EXPORT_SYMBOL_GPL(tcp_init_congestion_ops);
