/***************************************************
* Network packages filter
* Uses UNIX socket for packages filtering
*
*       File: nfilt.c 
* Created on: 15-04-2014
*     Author: Lyblinsky Alexander
****************************************************/

#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/types.h>
#include <linux/ktime.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/workqueue.h>

// EXPORT_SYMBOL(ip_output);

void hook_fn_out_bh(struct work_struct *work);


/*
* Structure to store data of regular
* IP packet, grabbed by hook function
* 
* PURPOSE: for processing in half bottom
* of hook interrupt handler
*/
typedef struct {
	struct sk_buff *skb;
	struct work_struct work;
} packet_data_t;



/*
* Workqueue for packets
*/
static struct workqueue_struct *packet_wq;



/*
* Hook function for IP packets,
* quiting from machine
*/
unsigned int hook_fn_out(unsigned int hooknum,
						 struct sk_buff *skb,
						 const struct net_device *in,
						 const struct net_device *out,
						 int (*okfn)(struct sk_buff *)) {

	packet_data_t *packet_data;

	// Filling tmp packet data
	packet_data = kmalloc(sizeof(packet_data_t), GFP_ATOMIC); 
	packet_data->skb = skb_copy(skb, GFP_ATOMIC);

	// Queuing task
	INIT_WORK(&(packet_data->work), hook_fn_out_bh);
	queue_work(packet_wq, &(packet_data->work)); 
	return NF_DROP;
}



/*
* Bottom half of hook function - interrupt
* handler for packets
*/ 
void hook_fn_out_bh(struct work_struct *work) {
	packet_data_t *packet_data = container_of(work, packet_data_t, work);
	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	network_header = (struct iphdr *)skb_network_header(packet_data->skb);

	printk(KERN_ALERT"[network animus]: [BH]: ----- packet catched\n");
	printk(KERN_ALERT"[network animus]: [BH]: IP packet saddr = %x, daddr = %x\n", network_header->saddr, network_header->daddr);

	// Print info about packet
	if (network_header->protocol == IPPROTO_TCP) {
		printk(KERN_ALERT"[network animus]: [BH]: TCP packet from intr!\n");
		tcp_header = (struct tcphdr *)tcp_hdr(packet_data->skb);
		printk(KERN_ALERT"[network animus]: [BH]: [TCP] packet sport %x, dport %x\n", tcp_header->source, tcp_header->dest);
	/*} else if (network_header->protocol == PROTOCOL_UDP_NUM) {
		printk(KERN_ALERT"[network animus]: UDP packet from intr!\n");*/
	} else {
		printk(KERN_ALERT"[network animus]: [BH]: packet unknown protocol\n");
	}

	// Send packet to post routing
	// ip_output(packet_data->skb);

	kfree_skb(packet_data->skb);
	kfree(packet_data);
}



/*
* Operations with hook function
*/
struct nf_hook_ops hook_ops;



/*
* Module initialization function
*/
static int __init filter_init(void) {
	printk(KERN_ALERT"[network animus]: alive\n");

	packet_wq = create_workqueue("nfilter_workqueue");
	if (packet_wq == NULL) {
		printk(KERN_ALERT"[network animus]: workqueue creation error!\n");
		return -1;
	} else {
		printk(KERN_ALERT"[network animus]: workqueue created successfully\n"); 
	}

	// Init hook operations
	hook_ops.hook = hook_fn_out;
	hook_ops.owner = THIS_MODULE;
	hook_ops.pf = PF_INET;
	hook_ops.hooknum = NF_INET_LOCAL_OUT;
	nf_register_hook(&hook_ops); 
	return 0;
}



/*
* Module cleanup function
*/
static void __exit filter_release(void) {
	printk(KERN_ALERT"[network animus]: released\n");
	nf_unregister_hook(&hook_ops);

	flush_workqueue(packet_wq);
	destroy_workqueue(packet_wq);
}


module_init(filter_init);
module_exit(filter_release);

MODULE_AUTHOR("Lyblinsky Alexander");
MODULE_DESCRIPTION("simple net firewall");
MODULE_LICENSE("GPL");
