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


#include "Program.h"


class Tagger : public Program {
 public:
  Tagger(Trafficclassifier &classifier);
  void load(uint8_t pipeline) override;
  void initBitvector(uint32_t size) override;
  void appendClassId(uint32_t id);

 private:
  std::vector<uint32_t> class_ids_;
};