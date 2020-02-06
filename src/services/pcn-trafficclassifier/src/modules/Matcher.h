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

#include "Matcher_dp.h"
#include "Program.h"

template <class T>
class Matcher : public Program {
 public:
  Matcher(Trafficclassifier &classifier, ProgramType program_type)
      : Program(classifier, program_type, matcher_code) {
    replaceAll(code_template_, "_FIELD",
               kFieldData[PROG_INDEX(program_type)].name);
    replaceAll(code_template_, "_TYPE",
               kFieldData[PROG_INDEX(program_type)].type);
  };

 protected:
  uint32_t current_bit_;
  std::vector<uint64_t> wildcard_bitvector_;

  std::string genCode(uint8_t pipeline) override {
    std::string code = Program::genCode(pipeline);

    if (hasWildcard()) {
      replaceAll(code, "_WILDCARD_PRESENT", "1");

      std::ostringstream wcard_vect;
      wcard_vect << "{" << wildcard_bitvector_[0];
      for (int i = 1; i < wildcard_bitvector_.size(); i++) {
        wcard_vect << ", " << wildcard_bitvector_[i];
      }
      wcard_vect << "}";
      replaceAll(code, "_WILDCARD_BV", wcard_vect.str());

    } else {
      replaceAll(code, "_WILDCARD_PRESENT", "0");
    }

    return code;
  }

  bool hasWildcard() {
    for (auto &it : wildcard_bitvector_) {
      if (it != 0) {
        return true;
      }
    }

    return false;
  }
};