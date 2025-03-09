int xdp_ingress_CONTAINER_NAME(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr eth_copy;
    struct iphdr iph_copy;
    struct tcphdr tcph_copy;

    // Parse Ethernet header
    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(struct ethhdr) > data_end)
        return XDP_PASS;

    // Check if the packet is IP
    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // Parse IP header
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)iph + sizeof(struct iphdr) > data_end)
        return XDP_PASS;

    if (iph->protocol != IP_TCP)
        return XDP_PASS;
    
    // Parse TCP header
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
    if ((void *)tcph + sizeof(struct tcphdr) > data_end)
        return XDP_PASS;

    if (!tcph->syn || tcph->ack) {
        return XDP_PASS;
    }
    struct label_header *lhh = (struct label_header *)(tcph + 1);

    __builtin_memcpy(&eth_copy, eth, sizeof(eth_copy));
    __builtin_memcpy(&iph_copy, iph, sizeof(iph_copy));
    __builtin_memcpy(&tcph_copy, tcph, sizeof(tcph_copy));

    if(bpf_xdp_adjust_head(ctx, -sizeof(struct label_header)))
        return XDP_PASS;
    iph_copy.tot_len += 7;
    
    data = (void *)(long) ctx->data;
    data_end = (void *)(long) ctx->data_end;
    if(data + 1 > data_end)
        return XDP_PASS;
    eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if (data + sizeof(*eth) + sizeof(*iph) > data_end)
        return XDP_PASS;

    iph = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) > data_end)
        return XDP_PASS;

    tcph = data + sizeof(*eth) + sizeof(*iph);
    if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph) + sizeof(struct label_header) > data_end)
        return XDP_PASS;

    lhh = data + sizeof(*eth) + sizeof(*iph) + sizeof(*tcph);
    struct label_header lh = {};
    strcpy(&lh.label, "CONTAINER_NAME");

    __builtin_memcpy(eth, &eth_copy, sizeof(*eth));
    __builtin_memcpy(iph, &iph_copy, sizeof(*iph));
    __builtin_memcpy(tcph, &tcph_copy, sizeof(*tcph));
    __builtin_memcpy(lhh, &lh, sizeof(*lhh));
    
    return XDP_PASS;
}


int tc_egress_CONTAINER_NAME(struct __sk_buff *skb) {
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;
    struct ethhdr eth_copy;
    struct iphdr iph_copy;
    struct tcphdr tcph_copy;
    struct label_header lh_copy;

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

    struct label_header *lhh = (struct label_header *)(tcph + 1);
    if ((void *)lhh + sizeof(struct label_header) > data_end)
        return TC_ACT_OK;
    
    if (bpf_skb_load_bytes(skb, 0, &eth_copy, sizeof(eth_copy)))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy)))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy)))
        return TC_ACT_OK;

    if (bpf_skb_load_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct tcphdr), &lh_copy, sizeof(lh_copy)))
        return TC_ACT_OK;

    if (bpf_skb_adjust_room(skb, -sizeof(struct label_header), BPF_ADJ_ROOM_NET, BPF_F_ADJ_ROOM_FIXED_GSO))
        return TC_ACT_OK;
    iph_copy.tot_len -= 7;

    if (bpf_skb_store_bytes(skb, 0, &eth_copy, sizeof(eth_copy), 0))
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr), &iph_copy, sizeof(iph_copy), 0))
        return TC_ACT_OK;

    if (bpf_skb_store_bytes(skb, sizeof(struct ethhdr) + sizeof(struct iphdr), &tcph_copy, sizeof(tcph_copy), 0))
        return TC_ACT_OK;

    struct key_type key = {};

    __builtin_memcpy(&key.src, &lh_copy.label, 7);
    strcpy(&key.dst, "CONTAINER_NAME");
    u8 decision = 0;
    u8 * decision_lookup = access_control.lookup(&key);
    if(decision_lookup!=0) {
        decision = *decision_lookup;
    }

    struct event_xdp event = {};
    __builtin_memcpy(event.source_label, key.src, sizeof(key.src));
    strcpy(&event.container_name, "CONTAINER_NAME");
    event.decision = decision;
    events_xdp.perf_submit(skb, &event, sizeof(event));
    
    if (decision == 0) {
        return TC_ACT_SHOT;
    }

    return TC_ACT_OK;
}