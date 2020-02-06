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

#pragma once

#include "Matcher.h"

template <class T>
class PrefixMatcher : public Matcher<T> {
  using Matcher<T>::program_type_;
  using Matcher<T>::classifier_;
  using Matcher<T>::code_template_;
  using Matcher<T>::bitvector_size_;
  using Matcher<T>::current_bit_;
  using Matcher<T>::wildcard_bitvector_;
  using Matcher<T>::replaceAll;

 public:
  PrefixMatcher(Trafficclassifier &classifier, ProgramType program_type)
      : Matcher<T>(classifier, program_type) {
    replaceAll(code_template_, "_PREFIX_MATCHER", "1");
  }

  void load(uint8_t pipeline) override {
    Program::load(pipeline);

    std::string table_name = kFieldData[PROG_INDEX(program_type_)].name +
                             "_rules_" + std::to_string(pipeline);
    auto table = classifier_.get_raw_table(table_name,
                                           PROG_INDEX(program_type_, pipeline));
    for (auto &it : bitvectors_) {
      table.set(&it.first, it.second.data());
    }
  }

  void initBitvector(uint32_t size) override {
    Program::initBitvector(size);
    bitvectors_.clear();
    current_bit_ = 0;
    wildcard_bitvector_ = std::vector<uint64_t>((bitvector_size_ - 1) / 64 + 1);
  }

  void appendValueBit(T value, uint32_t prefix_len) {
    uint32_t subvector = current_bit_ / 64;
    uint32_t subbit = current_bit_ % 64;

    T mask = 0;
    mask -= 1;
    mask <<= sizeof(T) * 8 - prefix_len;
    mask >>= sizeof(T) * 8 - prefix_len;

    value &= mask;
    struct LpmKey key = {prefix_len, value};

    // Set the bit for all values that match the new one
    bool present = false;
    for (auto &it : bitvectors_) {
      if (it.first == key) {
        present = true;
      }

      if ((it.first.key & mask) == value) {
        it.second[subvector] |= (uint64_t)1 << subbit;
      }
    }

    if (!present) {
      std::vector<uint64_t> bv = wildcard_bitvector_;
      bv[subvector] |= (uint64_t)1 << subbit;
      bitvectors_.push_back(
          std::pair<struct LpmKey, std::vector<uint64_t>>(key, bv));
    }

    current_bit_++;
  }

  void appendWildcardBit() {
    uint32_t subvector = current_bit_ / 64;
    uint32_t subbit = current_bit_ % 64;

    for (auto &it : bitvectors_) {
      it.second[subvector] |= (uint64_t)1 << subbit;
    }
    wildcard_bitvector_[subvector] |= (uint64_t)1 << subbit;

    current_bit_++;
  }

 private:
  struct LpmKey {
    uint32_t prefix_len;
    T key;

    bool operator==(const struct LpmKey &other) {
      return key == other.key && prefix_len == other.prefix_len;
    }
  };

  std::vector<std::pair<struct LpmKey, std::vector<uint64_t>>> bitvectors_;
};