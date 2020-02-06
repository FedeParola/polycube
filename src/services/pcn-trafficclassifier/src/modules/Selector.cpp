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


#include "Selector.h"
#include "Selector_dp.h"


Selector::Selector(Trafficclassifier &classifier)
    : Program(classifier, ProgramType::SELECTOR, selector_code),
      classification_enabled_(false) {};

std::string Selector::genCode(uint8_t pipeline) {
  std::string code = Program::genCode(pipeline);

  if (classification_enabled_) {
    replaceAll(code, "_CLASSIFY", "1");

  } else {
    replaceAll(code, "_CLASSIFY", "0");
  }

  return code;
}

void Selector::setClassificationEnabled(bool enabled) {
  classification_enabled_ = enabled;
}

void Selector::load() {
  Program::load(0);
}