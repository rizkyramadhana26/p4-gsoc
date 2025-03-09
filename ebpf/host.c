int tc_egress_HOST(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr eth_copy;
    struct iphdr iph_copy;
    struct tcphdr tcph_copy;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return TC_ACT_OK;

    // Check if the packet is IP
    if (eth->h_proto != htons(ETH_P_IP))
        return TC_ACT_OK;

    // Parse IP header
    struct iphdr *ip = (struct iphdr *)(eth + 1);
    if ((void *)ip + sizeof(struct iphdr) > data_end)
        return TC_ACT_OK;

    if (ip->protocol != IP_TCP)
        return TC_ACT_OK;
    
    // Parse TCP header
    struct tcphdr *tcph = (struct tcphdr *)(ip + 1);
    if ((void *)tcph + sizeof(struct tcphdr) > data_end)
        return TC_ACT_OK;

    if (!tcph->syn || tcph->ack) {
        return TC_ACT_OK;
    }

    struct label_header lh = {};
    strcpy(&lh.label, "HOST");
    
    if (bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy)))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy)))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy)))
        return TC_ACT_OK;

    if (bpf_skb_adjust_room(skb, sizeof(struct label_header), BPF_ADJ_ROOM_MAC, BPF_F_ADJ_ROOM_FIXED_GSO))
        return TC_ACT_OK;
    iph_copy.tot_len += 7;

    if (bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0))
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy), 0))
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy), 0))
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), &lh, sizeof(lh), 0))
        return TC_ACT_OK;
        
    return TC_ACT_OK;

}