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


#include "../Trafficclassifier.h"


class Program {
 public:
  Program(Trafficclassifier &classifier, ProgramType program_type,
          std::string code_template_base);
  bool isLoaded(uint8_t pipeline);
  virtual void load(uint8_t pipeline);
  void unload(uint8_t pipeline);
  void setNext(uint32_t program_index);
  virtual void initBitvector(uint32_t size);
  
 protected:
  ProgramType program_type_;
  Trafficclassifier &classifier_;
  bool loaded_[2];
  uint32_t next_program_;
  std::string code_template_;
  uint32_t bitvector_size_;

  virtual std::string genCode(uint8_t pipeline);
  void replaceAll(std::string &str, const std::string &from,
                  const std::string &to);
};