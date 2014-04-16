/*****************************************
* Network packages filter
* Uses UNIX socket for packages filtering
*
*       File: nfilt.c 
* Created on: 15-04-2014
*     Author: Lyblinxky Alexander
******************************************/

#include <linux/module.h>
#include <linux/kernel.h>

#include <linux/types.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>


/*
* Hook function for IP packets,
* quiting from machine
*/
unsigned int hook_function_out(unsigned int hooknum,
									  struct sk_buff *skb,
									  const struct net_device *in,
									  const struct net_device *out,
									  int (*okfn)(struct sk_buff *)) {
	printk(KERN_ALERT"[network animus]: packet catched\n");
	return NF_ACCEPT;
}

struct nf_hook_ops hook_ops;

/*
* Module initialization function
*/
static int __init filter_init(void) {
	printk(KERN_ALERT"[network animus]: alive\n");
	hook_ops.hook = hook_function_out;
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
}

module_init(filter_init);
module_exit(filter_release);

MODULE_AUTHOR("Lyblinsky Alexander");
MODULE_DESCRIPTION("simple net firewall");
MODULE_LICENSE("GPL");
