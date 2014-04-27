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
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <linux/workqueue.h>

// EXPORT_SYMBOL(ip_output);

void hook_fn_out_bh(struct work_struct *work);


/*
* Global parameters
*/
static __u32 mod_destination_ip = 0x1dcc645d;
module_param_named(modified_dest_ip, mod_destination_ip, uint, 0644);
MODULE_PARM_DESC(mod_destination_ip, "Value for modifying destination ip");

static __u16 mod_source_port = 0x4fd9;
module_param_named(modified_source_port, mod_source_port, ushort, 0644);
MODULE_PARM_DESC(mod_source_port, "Value for modifying source port");

static __u16 filt_destination_port = 0x5000;
module_param_named(filtering_destination_port, filt_destination_port, ushort, 0644);
MODULE_PARM_DESC(filt_destination_port, "Value for filtering dest port");


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

	// packet_data_t *packet_data;

	// Filling tmp packet data
	/*
	packet_data = kmalloc(sizeof(packet_data_t), GFP_ATOMIC); 
	packet_data->skb = skb_copy(skb, GFP_ATOMIC);
	*/ 
	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	network_header = (struct iphdr *)skb_network_header(skb);

	// Print IP info
	printk(KERN_INFO"[network animus]: ----- packet catched\n");
	printk(KERN_INFO"[network animus]: IP packet saddr = %x, daddr = %x\n", network_header->saddr, network_header->daddr);

	// Print info about TCP packet
	if (network_header->protocol == IPPROTO_TCP) {
		printk(KERN_INFO"[network animus]: TCP packet from intr!\n");
		tcp_header = (struct tcphdr *)tcp_hdr(skb);
		printk(KERN_INFO"[network animus]: [TCP] packet sport %x, dport %x\n", tcp_header->source, tcp_header->dest);

		// Filtrations
		if (tcp_header->dest == filt_destination_port) {
			printk(KERN_INFO"[network animus]: i will filt you\n");
			printk(KERN_INFO"[network animus]: [modify]: changed destination addr ip from %x to %x\n", network_header->daddr, mod_destination_ip);
			network_header->daddr = mod_destination_ip;
			printk(KERN_INFO"[network animus]: [modify]: changed source port from %x to %x", tcp_header->source, mod_source_port);
			tcp_header->source = mod_source_port;
			return NF_ACCEPT;
		}
	} else {
		printk(KERN_INFO"[network animus]: packet unknown protocol\n");
	}

	printk(KERN_INFO"[network animus]: packet dropped into hell\n");

	// Queuing task
	/*
	INIT_WORK(&(packet_data->work), hook_fn_out_bh);
	queue_work(packet_wq, &(packet_data->work)); 
	*/
	return NF_DROP;
}



/*
* Bottom half of hook function - interrupt
* handler for packets
* 
* ->unused<- cause of problems with exporting
* ip_output. Should be in /include/net/ip.h
*/ 
void hook_fn_out_bh(struct work_struct *work) {
	packet_data_t *packet_data = container_of(work, packet_data_t, work);
	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	network_header = (struct iphdr *)skb_network_header(packet_data->skb);

	printk(KERN_INFO"[network animus]: [BH]: ----- packet catched\n");
	printk(KERN_INFO"[network animus]: [BH]: IP packet saddr = %x, daddr = %x\n", network_header->saddr, network_header->daddr);

	// Print info about packet
	if (network_header->protocol == IPPROTO_TCP) {
		printk(KERN_INFO"[network animus]: [BH]: TCP packet from intr!\n");
		tcp_header = (struct tcphdr *)tcp_hdr(packet_data->skb);
		printk(KERN_INFO"[network animus]: [BH]: [TCP] packet sport %x, dport %x\n", tcp_header->source, tcp_header->dest);
	/*} else if (network_header->protocol == PROTOCOL_UDP_NUM) {
		printk(KERN_INFO"[network animus]: UDP packet from intr!\n");*/
	} else {
		printk(KERN_INFO"[network animus]: [BH]: packet unknown protocol\n");
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
	printk(KERN_ALERT"[network animus]: new session started\n");
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
