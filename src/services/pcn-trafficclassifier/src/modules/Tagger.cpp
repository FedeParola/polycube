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


#include "Tagger.h"
#include "Tagger_dp.h"


Tagger::Tagger(Trafficclassifier &classifier)
    : Program(classifier, ProgramType::TAGGER, tagger_code) {};

void Tagger::initBitvector(uint32_t size) {
  Program::initBitvector(size);
  class_ids_.clear();
  class_ids_.reserve(size);
}

void Tagger::load(uint8_t pipeline) {
  Program::load(pipeline);

  const uint16_t index64[64] = {
      0,  47, 1,  56, 48, 27, 2,  60, 57, 49, 41, 37, 28, 16, 3,  61,
      54, 58, 35, 52, 50, 42, 21, 44, 38, 32, 29, 23, 17, 11, 4,  62,
      46, 55, 26, 59, 40, 36, 15, 53, 34, 51, 20, 43, 31, 22, 10, 45,
      25, 39, 14, 33, 19, 30, 9,  24, 13, 18, 8,  12, 7,  6,  5,  63};

  std::string table_name = std::string("index64_") + std::to_string(pipeline);
  auto table = classifier_.get_array_table<uint16_t>(
      table_name, PROG_INDEX(TAGGER, pipeline));

  for (int i = 0; i < 64; i++) {
    table.set(i, index64[i]);
  }

  table_name = std::string("class_ids_") + std::to_string(pipeline);
  auto class_ids_table = classifier_.get_array_table<uint32_t>(
      table_name, PROG_INDEX(TAGGER, pipeline));

  for (int i = 0; i < class_ids_.size(); i++) {
    class_ids_table.set(i, class_ids_[i]);
  }
}

void Tagger::appendClassId(uint32_t id) {
  class_ids_.push_back(id);
}