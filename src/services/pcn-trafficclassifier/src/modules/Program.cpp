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

#include "Program.h"

Program::Program(Trafficclassifier &classifier, ProgramType program_type,
                 std::string code_template_base)
    : classifier_(classifier),
      program_type_(program_type),
      code_template_(code_template_base),
      loaded_{false},
      bitvector_size_(0) {};

bool Program::isLoaded(uint8_t pipeline) {
  return loaded_[pipeline];
}

void Program::load(uint8_t pipeline) {
  std::string ingress_code = genCode(pipeline);
  std::string egress_code = ingress_code;

  replaceAll(ingress_code, "_DIRECTION", "ingress");
  replaceAll(egress_code, "_DIRECTION", "egress");

  if (isLoaded(pipeline)) {
    classifier_.del_program(PROG_INDEX(program_type_, pipeline),
                            polycube::service::ProgramType::INGRESS);
    classifier_.del_program(PROG_INDEX(program_type_, pipeline),
                            polycube::service::ProgramType::EGRESS);
  }

  classifier_.add_program(ingress_code, PROG_INDEX(program_type_, pipeline),
                          polycube::service::ProgramType::INGRESS);
  classifier_.add_program(egress_code, PROG_INDEX(program_type_, pipeline),
                          polycube::service::ProgramType::EGRESS);

  loaded_[pipeline] = true;
}

void Program::unload(uint8_t pipeline) {
  if (isLoaded(pipeline)) {
    classifier_.del_program(PROG_INDEX(program_type_, pipeline),
                            polycube::service::ProgramType::INGRESS);
    classifier_.del_program(PROG_INDEX(program_type_, pipeline),
                            polycube::service::ProgramType::EGRESS);
    loaded_[pipeline] = true;
  }
}

void Program::setNext(uint32_t program_index) {
  next_program_ = program_index;
}

void Program::initBitvector(uint32_t size) {
  bitvector_size_ = size;
}

std::string Program::genCode(uint8_t pipeline) {
  std::string code(code_template_);
  replaceAll(code, "_SUBVECTS_COUNT",
             std::to_string((bitvector_size_ - 1) / 64 + 1));
  replaceAll(code, "_CLASSES_COUNT", std::to_string(bitvector_size_));
  replaceAll(code, "_NEXT", std::to_string(next_program_));
  replaceAll(code, "_PIPELINE", std::to_string(pipeline));

  return code;
}

void Program::replaceAll(std::string &str, const std::string &from,
                         const std::string &to) {
  if (from.empty())
    return;
  size_t start_pos = 0;
  while ((start_pos = str.find(from, start_pos)) != std::string::npos) {
    str.replace(start_pos, from.length(), to);
    start_pos += to.length();
  }
}