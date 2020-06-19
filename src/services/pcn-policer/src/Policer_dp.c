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


#include <bcc/helpers.h>


enum {
  ACTION_PASS,
  ACTION_LIMIT,
  ACTION_DROP
};

struct contract {
  u8 action;
  s64 counter;  // Counter of bits that can still be forwarded in the current
                // window
};

#define MAX_CONTRACTS 100000

#if POLYCUBE_PROGRAM_TYPE == 1  // EGRESS
BPF_TABLE("extern", int, struct contract, default_contract, 1);
BPF_TABLE("extern", u32, struct contract, contracts, MAX_CONTRACTS);
#else  // INGRESS
BPF_TABLE_SHARED("array", int, struct contract, default_contract, 1);
BPF_TABLE_SHARED("hash", u32, struct contract, contracts, MAX_CONTRACTS);
#endif


static inline int limit_rate(struct CTXTYPE *ctx, struct contract *contract) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  
  int size = (data_end - data) * 8;
  
  if (contract->counter < size) {
    return RX_DROP;
  }
  
  __sync_fetch_and_add(&contract->counter, -size);
  
  return RX_OK;
}

static __always_inline
int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  int zero = 0;

  // Retrieve contract
  struct contract *contract = contracts.lookup(&md->traffic_class);
  if (!contract) {
    contract = default_contract.lookup(&zero);
    if (!contract) {
      pcn_log(ctx, LOG_ERR, "Cannot access default contract");
      return RX_DROP;
    }
  }

  // Apply action
  switch (contract->action) {
    case ACTION_PASS:
      return RX_OK;
      break;

    case ACTION_LIMIT:
      return limit_rate(ctx, contract);
      break;

    case ACTION_DROP:
      return RX_DROP;
      break;
  }

  pcn_log(ctx, LOG_ERR, "Unknown action");
  return RX_DROP;
}