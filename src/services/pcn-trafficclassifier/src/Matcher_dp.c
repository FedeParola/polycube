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
// _PREFIX_MATCHER   whether matching is based on lpm trie (1) or hash map (0)
// _FIELD            packet field to perform the match on
// _TYPE             c type of the matching field
// _CLASSES_COUNT    number of traffic classes
// _WILDCARD_PRESENT whether there is a wildcard to match on (1 true, 0 false)
// _WILDCARD_BV      c immediate representation of the wildcard bitvector
// _NEXT             index of the next program in the classification pipeline


#include <bcc/helpers.h>


#define _DIRECTION_PROGRAM


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

#if _PREFIX_MATCHER
struct lpm_key {
  u32 prefix_len;
  _TYPE key;
};

#ifdef ingress_PROGRAM
BPF_LPM_TRIE(_FIELD_rules__PIPELINE, struct lpm_key, struct bitvector,
             _CLASSES_COUNT);
__attribute__((section("maps/shared")))
struct _FIELD_rules__PIPELINE_table_t ___FIELD_rules__PIPELINE;

#else
BPF_TABLE("extern", struct lpm_key, struct bitvector, _FIELD_rules__PIPELINE,
          _CLASSES_COUNT);
#endif

#else

// Size of the table is _CLASSES_COUNT + 1 to handle cases of l4matcher where
// both tcp and udp are set by a single traffic class (e.g. a class with
// dport set but not l4proto)
#ifdef ingress_PROGRAM
BPF_TABLE_SHARED("hash", _TYPE, struct bitvector, _FIELD_rules__PIPELINE,
                 _CLASSES_COUNT + 1);

#else
BPF_TABLE("extern", _TYPE, struct bitvector, _FIELD_rules__PIPELINE,
          _CLASSES_COUNT + 1);
#endif
#endif


static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: processing packet");

#if _WILDCARD_PRESENT
  struct bitvector wildcard_bv = {
    _WILDCARD_BV
  };
#endif

  int zero = 0;
  struct pkt_headers *pkt = _DIRECTION_packet__PIPELINE.lookup(&zero);
  if (!pkt) {
    return RX_DROP;
  }

#if _PREFIX_MATCHER
  struct lpm_key key = {sizeof(_TYPE) * 8, pkt->_FIELD};
#else
  _TYPE key = pkt->_FIELD;
#endif

  struct bitvector *rule_bv = _FIELD_rules__PIPELINE.lookup(&key);

  if (!rule_bv) {
#if _WILDCARD_PRESENT
    pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: no match found, using wildcard");
    rule_bv = &wildcard_bv;
#else

    pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: no match found, early stop of classification");
    return RX_OK;
#endif
  } else {
    pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: match found");
  }
  
  struct bitvector *pkt_bv = _DIRECTION_pkt_bitvector__PIPELINE.lookup(&zero);
  if (!pkt_bv) {
    return RX_DROP;
  }

  bool is_all_zero = true;

  for (int i = 0; i < _SUBVECTS_COUNT; i++) {
    pkt_bv->bits[i] &= rule_bv->bits[i];

    if (pkt_bv->bits[i]) {
      is_all_zero = false;
    }
  }

  if (is_all_zero) {
    pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: empty bitvector, early stop of classification");
    return RX_OK;
  }

  call__DIRECTION_program(ctx, _NEXT);

  return RX_DROP;
}