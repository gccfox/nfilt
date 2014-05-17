/***************************************************************
* TASK:
* Write network packages filter. Accept all TCP apckets with 
* destiantion port value equals to filt_destination_port, and
* drop others. All packets, that accepted will be modifyed by
* filter:
*   1) Changed destination IP to mod_destination_ip
*   2) Changed source port to mod_source_port
*   3) Changed first byte in data of packet to mod_first_byte
*
*       File: nfilt.c 
* Created on: 15-04-2014
*     Author: Lyblinsky Alexander
***************************************************************/

#include <linux/module.h>
#include <linux/kernel.h> 
#include <linux/types.h>
#include <linux/ktime.h>
#include <linux/workqueue.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <net/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h> 


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

static __u16 mod_first_byte = 0x70;
module_param_named(modified_first_byte, mod_first_byte, ushort, 0644);
MODULE_PARM_DESC(mod_first_byte, "Value of first byte in data of packet to be modified");



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
	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	char *data;

    // Filling tmp packet data 
	packet_data = kmalloc(sizeof(packet_data_t), GFP_ATOMIC); 
	packet_data->skb = skb_copy(skb, GFP_ATOMIC);

	if (packet_data->skb == NULL) {
		printk(KERN_ALERT"[network animus]: skb_copy() error\n");
	} else {
        // Queuing task for print data info
        INIT_WORK(&(packet_data->work), hook_fn_out_bh);
        queue_work(packet_wq, &(packet_data->work)); 
    }

    // Start packet analyse
	network_header = (struct iphdr *)skb_network_header(skb);

	// Print info about TCP packet
	if (network_header->protocol == IPPROTO_TCP) {
		tcp_header = (struct tcphdr *)tcp_hdr(skb);

		// Filtrations
		if (tcp_header->dest == filt_destination_port) {
			network_header->daddr = mod_destination_ip;
			tcp_header->source = mod_source_port;
            data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
            data[0] = mod_first_byte;
            skb->ip_summed = CHECKSUM_UNNECESSARY;
			return NF_ACCEPT;
		}
	} 
    return NF_DROP;
}



/*
* Bottom half of hook function - interrupt
* handler for packets
* 
*/ 
void hook_fn_out_bh(struct work_struct *work) {
	packet_data_t *packet_data;
	struct iphdr *network_header;
	struct tcphdr *tcp_header;
	struct sk_buff *skb;
    char *data;
    int i = 0;

	packet_data = container_of(work, packet_data_t, work);
	skb = packet_data->skb;
	network_header = (struct iphdr *)skb_network_header(skb);

	if (skb == NULL) {
		printk(KERN_ALERT"[network animus]: skb is NULL\n");
		return;
	}

	// Print IP info
    printk(KERN_INFO"[network animus]:[------BEGIN-OF-PACKET------] \n");
	printk(KERN_INFO"[network animus]: [BH]: [packet catched]\n");
	printk(KERN_INFO"[network animus]: [BH]: [IP] packet source IP addr = %x, destination IP addr = %x\n", network_header->saddr, network_header->daddr);

    // Continue work with TCP packets only
	if (network_header->protocol == IPPROTO_TCP) {
		printk(KERN_INFO"[network animus]: [BH]: [TCP] packet recognized\n");
		tcp_header = (struct tcphdr *)tcp_hdr(skb);
		printk(KERN_INFO"[network animus]: [BH]: [TCP] packet source port %x, destination port %x\n", tcp_header->source, tcp_header->dest);

        // Print first 15 bytes of data
        printk(KERN_INFO"[network_animus]: [BH]: first 15 bytes of packet data:\n");
        data = (char *)((unsigned char *)tcp_header + (tcp_header->doff * 4));
        for (i = 0; i < 15; i++) {
            printk(KERN_INFO"%c", data[i]);
        } 
        printk(KERN_INFO"\n"); 

		// Filtrations
		if (tcp_header->dest == filt_destination_port) {
			printk(KERN_INFO"[network animus]: [BH]: [filtration]\n");
			printk(KERN_INFO"[network animus]: [BH]: [modify]: changed destination IP addr ip from %x to %x\n", network_header->daddr, mod_destination_ip); 
			printk(KERN_INFO"[network animus]: [BH]: [modify]: changed source port from %x to %x\n", tcp_header->source, mod_source_port);
			printk(KERN_INFO"[network animus]: [BH]: [modify]: changed first data byte from %x to %x\n", data[0], mod_first_byte);
        }
	} else {
		printk(KERN_INFO"[network animus]: [BH]: [SUDENNESS] packet unknown protocol\n");
	}
    printk(KERN_INFO"[network animus]:[-------END-OF-PACKET-------] \n\n");
}



/*
* Operations with hook function
*/
struct nf_hook_ops hook_ops;



/*
* Module initialization function
*/
static int __init filter_init(void) {
	printk(KERN_ALERT"[network animus]: [alive]\n");

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
	printk(KERN_ALERT"[network animus]: [***]: new session started\n");
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
