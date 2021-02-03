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
// DIRECTION        direction (ingress/egress) of the program
// SUBVECTS_COUNT   number of 64 bits elements composing the bitvector
// PREFIX_MATCHER   whether matching is based on lpm trie (1) or hash map (0)
// FIELD            packet field to perform the match on
// TYPE             c type of the matching field
// CLASSES_COUNT    number of traffic classes
// WILDCARD         whether there is a wildcard to match on (1 true, 0 false)


{
#if _PREFIX_MATCHER
  struct _FIELD_lpm_key key = {sizeof(_TYPE) * 8, pkt._FIELD};
#else
  _TYPE key = pkt._FIELD;
#endif

  struct bitvector *bv = _FIELD_rules.lookup(&key);

  if (!bv) {
#if !_PREFIX_MATCHER && _WILDCARD
    bv = _FIELD_wildcard_bv.lookup(&zero);
    if (!bv) {
      return RX_DROP;
    }
#else

    pcn_log(ctx, LOG_TRACE,
            "_DIRECTION _FIELD matcher: no match found, early stop of "
            "classification");
    return RX_OK;
#endif
  }

  bitvectors[current_bitvector] = bv;

  pcn_log(ctx, LOG_TRACE, "_DIRECTION _FIELD matcher: match found");

  current_bitvector++;
}

