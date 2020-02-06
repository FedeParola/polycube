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


template<class T> class HashMatcher : public Matcher<T> {
  using Matcher<T>::program_type_;
  using Matcher<T>::classifier_;
  using Matcher<T>::code_template_;
  using Matcher<T>::bitvector_size_;
  using Matcher<T>::field_;
  using Matcher<T>::current_bit_;
  using Matcher<T>::wildcard_bitvector_;
  using Matcher<T>::replaceAll;

 public:
  HashMatcher(Trafficclassifier &classifier, ProgramType program_type, std::string field, std::string field_type):
      Matcher<T>(classifier, program_type, field, field_type) {
    replaceAll(code_template_, "_PREFIX_MATCHER", "0");
  }

  void load() override {
    Program::load();

    auto table = classifier_.get_raw_table(field_ + "_rules", PROGRAM_INDEX(program_type_));
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

  void appendValueBit(T value) {
    uint32_t subvector = current_bit_ / 64;
    uint32_t subbit = current_bit_ % 64;

    if (bitvectors_.count(value) == 0) {
      bitvectors_[value] = wildcard_bitvector_;
    }
    bitvectors_[value][subvector] |= 1 << subbit;

    current_bit_++;
  }

  void appendValuesBit(std::vector<T> values) {
    uint32_t subvector = current_bit_ / 64;
    uint32_t subbit = current_bit_ % 64;

    for (auto value : values) {
      if (bitvectors_.count(value) == 0) {
        bitvectors_[value] = wildcard_bitvector_;
      }
      bitvectors_[value][subvector] |= 1 << subbit;
    }

    current_bit_++;
  }

  void appendWildcardBit() {
    uint32_t subvector = current_bit_ / 64;
    uint32_t subbit = current_bit_ % 64;

    for (auto &it : bitvectors_) {
      it.second[subvector] |= 1 << subbit;
    }
    wildcard_bitvector_[subvector] |= 1 << subbit;

    current_bit_++;
  }

 private:
  std::unordered_map<T, std::vector<uint64_t>> bitvectors_;
};