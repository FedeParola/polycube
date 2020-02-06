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
// _DIRECTION direction (ingress/egress) of the program
// _CLASSIFY  whether classification is enabled (0/1)
// _NEXT      index of the next program in the classification pipeline


#include <bcc/helpers.h>


static int handle_rx(struct CTXTYPE *ctx, struct pkt_metadata *md) {
  pcn_log(ctx, LOG_TRACE, "_DIRECTION selector: processing packet");

#if _CLASSIFY
  call__DIRECTION_program(ctx, _NEXT);
  
  return RX_DROP;

#else
  return RX_OK;
#endif
}