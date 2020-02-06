/*
 * Copyright 2020 The Polycube Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


// Template parameters:
// _DIRECTION        direction (ingress/egress) of the program
// _PIPELINE         the classification pipeline this program belongs to (0/1)
// _SUBVECTS_COUNT   number of 64 bits elements composing the bitvector
// _NEXT             index of the next program in the classification pipeline


#include <bcc/helpers.h>

#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>


struct eth_hdr {
  __be64 dst : 48;
  __be64 src : 48;
  __be16 proto;
} __attribute__((packed));

struct pkt_headers {
  __be64 smac;
  __be64 dmac;
  __be16 ethtype;
  __be32 srcip;
  __be32 dstip;
      u8 l4proto;
  __be16 sport;
  __be16 dport;
};

BPF_TABLE("extern", int, struct pkt_headers, _DIRECTION_packet__PIPELINE, 1);

struct bitvector {
  u64 bits[_SUBVECTS_COUNT];
};

BPF_TABLE("extern", int, struct bitvector, _DIRECTION_pkt_bitvector__PIPELINE,
          1);


static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_TRACE, "_DIRECTION parser: processing packet");

  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;

  struct eth_hdr *eth = data;
  if (data + sizeof(*eth) > data_end) {
    return RX_DROP;
  }

  struct pkt_headers pkt = {0};

  pkt.smac = eth->src;
  pkt.dmac = eth->dst;
  pkt.ethtype = eth->proto;

  if (eth->proto != htons(ETH_P_IP)) {
    goto CONTINUE;
  }

  struct iphdr *ip = data + sizeof(*eth);
  if ((void *)ip + sizeof(*ip) > data_end) {
    return RX_DROP;
  }

  pkt.srcip = ip->saddr;
  pkt.dstip = ip->daddr;
  pkt.l4proto = ip->protocol;

  if (ip->protocol == IPPROTO_TCP) {
    struct tcphdr *tcp = (void *)ip + 4*ip->ihl;
    if ((void *)tcp + sizeof(*tcp) > data_end) {
        return RX_DROP;
    }

    pkt.sport = tcp->source;
    pkt.dport = tcp->dest;

  } else if (ip->protocol == IPPROTO_UDP) {
    struct udphdr *udp = (void *)ip + 4*ip->ihl;
    if ((void *)udp + sizeof(*udp) > data_end) {
        return RX_DROP;
    }
    
    pkt.sport = udp->source;
    pkt.dport = udp->dest;
  }

CONTINUE:;
  int zero = 0;
  _DIRECTION_packet__PIPELINE.update(&zero, &pkt);

  struct bitvector pkt_bv;

  // Initialize packet bitvector
  for (int i = 0; i < _SUBVECTS_COUNT; i++) {
    pkt_bv.bits[i] = 0xffffffffffffffff;
  }

  _DIRECTION_pkt_bitvector__PIPELINE.update(&zero, &pkt_bv);


  call__DIRECTION_program(ctx, _NEXT);

  return RX_DROP;
}