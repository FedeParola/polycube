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
// _DIRECTION      direction (ingress/egress) of the program
// _PIPELINE       the classification pipeline this program belongs to (0/1)
// _SUBVECTS_COUNT number of 64 bits elements composing the bitvector
// _CLASSES_COUNT  number of traffic classes


#include <bcc/helpers.h>


#define _DIRECTION_PROGRAM

#ifdef ingress_PROGRAM
BPF_TABLE_SHARED("array", int, u16, index64__PIPELINE, 64);
#else
BPF_TABLE("extern", int, u16, index64__PIPELINE, 64);
#endif

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

BPF_TABLE_SHARED("percpu_array", int, struct pkt_headers,
                 _DIRECTION_packet__PIPELINE, 1);

struct bitvector {
  u64 bits[_SUBVECTS_COUNT];
};

BPF_TABLE_SHARED("percpu_array", int, struct bitvector,
                 _DIRECTION_pkt_bitvector__PIPELINE, 1);

#ifdef ingress_PROGRAM
BPF_TABLE_SHARED("array", int, u32, class_ids__PIPELINE, _CLASSES_COUNT);
#else
BPF_TABLE("extern", int, u32, class_ids__PIPELINE, _CLASSES_COUNT);
#endif


static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_TRACE, "_DIRECTION tagger: processing packet");

  int zero = 0;
  struct bitvector *pkt_bv = _DIRECTION_pkt_bitvector__PIPELINE.lookup(&zero);
  if (!pkt_bv) {
    return RX_DROP;
  }

  int matching_class_index = -1;
  u16 *matching_res;
  for (int i = 0; i < _SUBVECTS_COUNT; i++) {
    u64 bits = (pkt_bv->bits)[i];
    if (bits != 0) {
      int index = (int)(((bits ^ (bits - 1)) * 0x03f79d71b4cb0a89) >> 58);
      
      matching_res = index64__PIPELINE.lookup(&index);
      if (!matching_res) {
        return RX_DROP;
      }

      matching_class_index = *matching_res + i * 64;
    }
  }

  if (matching_class_index >= 0) {
    u32 *id = class_ids__PIPELINE.lookup(&matching_class_index);
    if (!id) {
      return RX_DROP;
    }

    // For tc programs class is stored into skb->mark field
    // For xdp programs class is stored into the first four bytes
    // of metadata buffer

#ifdef POLYCUBE_XDP
    u32 *class_metadata;
    void *data = (void *)(unsigned long)ctx->data;
    void *data_meta = (void *)(unsigned long)ctx->data_meta;

    class_metadata = data_meta;
    if ((void *)class_metadata + sizeof(*class_metadata) > data) {
      // Need to resize packet buffer to host metadata
      bpf_xdp_adjust_meta(ctx, (int)-sizeof(*class_metadata));
      
      data = (void *)(unsigned long)ctx->data;
      data_meta = (void *)(unsigned long)ctx->data_meta;
      
      class_metadata = data_meta;
      if ((void *)class_metadata + sizeof(*class_metadata) > data) {
        pcn_log(ctx, LOG_ERR, "_DIRECTION tagger: unable to allocate space for packet metadata");
        return RX_OK;
      }

      *class_metadata = *id;
    }
#else

    ctx->mark = *id;
#endif

    pcn_log(ctx, LOG_TRACE, "_DIRECTION tagger: packet tagged with class %d",
            *id);
  }

  return RX_OK;
}
