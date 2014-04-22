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

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/ip.h>

#include <linux/workqueue.h>
#define PROTOCOL_TCP_NUM    6U
#define PROTOCOL_UDP_NUM    17U

void hook_fn_out_bh(struct work_struct *work);


/*
* Structure to store data of regular
* IP packet, grabbed by hook function
* 
* PURPOSE: for processing in half bottom
* of hook interrupt handler
*/
typedef struct {
	struct iphdr *network_header;
	sk_buff_data_t transport_header;
	sk_buff_data_t mac_header;
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
	struct iphdr *network_header;
	network_header = (struct iphdr *)skb_network_header(skb);

	// Print info about packet
	if (network_header->protocol == PROTOCOL_TCP_NUM) {
		printk(KERN_ALERT"[network animus]: TCP packet from intr!\n");
	} else if (network_header->protocol == PROTOCOL_UDP_NUM) {
		printk(KERN_ALERT"[network animus]: UDP packet from intr!\n");
	} else {
		printk(KERN_ALERT"[network animus]: packet from intr!\n");
	}

	// Filling packet data
	packet_data = kmalloc(sizeof(packet_data_t), GFP_ATOMIC); 
	packet_data->network_header = network_header;

	// Queuing task
	INIT_WORK(&(packet_data->work), hook_fn_out_bh);
	queue_work(packet_wq, &(packet_data->work)); 
	return NF_ACCEPT;
}


/*
* Bottom half of hook function - interrupt
* hadnler for packets
*/ 
void hook_fn_out_bh(struct work_struct *work) {
	packet_data_t *packet_data = container_of(work, packet_data_t, work);
	//printk(KERN_ALERT"[network animus]: packet catched IP: %d\n", packet_data->network_header->id); 

	printk(KERN_ALERT"[network animus]: packet catched\n");

	kfree(packet_data);
}


/*
*
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
	//flush_scheduled_work();
}


module_init(filter_init);
module_exit(filter_release);

MODULE_AUTHOR("Lyblinsky Alexander");
MODULE_DESCRIPTION("simple net firewall");
MODULE_LICENSE("GPL");
