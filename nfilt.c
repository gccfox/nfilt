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

#include <linux/workqueue.h>

void hook_fn_out_bh(struct work_struct *work);
//DECLARE_WORK(hook_work, hook_fn_out_bh);


/*
* Structure to store data of regular
* IP packet, grabbed by hook function
* 
* PURPOSE: for processing in half bottom
* of hook interrupt handler
*/
typedef struct {
	sk_buff_data_t iphdr;
	sk_buff_data_t transport_header;
	sk_buff_data_t network_header;
	sk_buff_data_t mac_header;
	struct work_struct work;
} hook_data_t;


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

	hook_data_t *hook_data;
	hook_data = kmalloc(sizeof(hook_data_t), GFP_ATOMIC);
	INIT_WORK(&(hook_data->work), hook_fn_out_bh);
	queue_work(packet_wq, &(hook_data->work)); 
	return NF_ACCEPT;
}


/*
* Bottom half of hook function - interrupt
* hadnler for packets
*/ 
void hook_fn_out_bh(struct work_struct *work) {
	hook_data_t *hook_data = container_of(work, hook_data_t, work);
	printk(KERN_ALERT"[network animus]: packet catched\n");
	kfree(hook_data);
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
