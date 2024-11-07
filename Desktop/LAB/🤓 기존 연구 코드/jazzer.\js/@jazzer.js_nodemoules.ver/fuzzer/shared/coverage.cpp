// Copyright 2022 Code Intelligence GmbH
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
#include "coverage.h"

#include <iostream>

extern "C" { // C++ 코드에서 C 스타일 함수 호출을 사용하기 위한 구문, 얘네는 LibFuzzer에서 코드 커버리지를 추적할 때 사용하는 두 가지 함수
void __sanitizer_cov_8bit_counters_init(uint8_t *start, uint8_t *end);
void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg, // 커버리지 카운터(코드 실행 정보를 기록하는 카운터)를 초기화
                              const uintptr_t *pcs_end); // 프로그램 카운터(PC) 테이블을 초기화하는 기능
}

namespace {
// We register an array of 8-bit coverage counters with libFuzzer. The array is
// populated from JavaScript using Buffer.
uint8_t *gCoverageCounters = nullptr; // 코드 커버리지 카운터 배열을 저장하는 포인터.

// PC-Table is used by libfuzzer to keep track of program addresses
// corresponding to coverage counters. The flags determine whether the
// corresponding counter is the beginning of a function; we don't currently use
// it. // PC-Table은 libfuzzer에서 커버리지 카운터에 해당하는 프로그램 주소를 추적하는 데 사용됩니다. 
// 플래그는 해당 카운터가 함수의 시작인지 여부를 결정하며, 현재는 이를 사용하지 않습니다.
struct PCTableEntry {
  uintptr_t PC, PCFlags;
};

// The array of supplementary information for coverage counters. Each entry
// corresponds to an entry in gCoverageCounters; since we don't know the actual
// addresses of our counters in JS land, we fill this table with fake
// information.
// JavaScript 코드 내부에서는 그 카운터가 어디에 위치하는지(메모리 주소)를 정확히 알 수 없기 때문에, 그 대신 임시로 가짜 데이터를 채워 넣는다.
PCTableEntry *gPCEntries = nullptr;
} // namespace


void RegisterCoverageMap(const Napi::CallbackInfo &info) { 
// JavaScript로부터 제공된 커버리지 데이터를 처리하는 함수
// Napi::CallbackInfo는 JavaScript 함수 호출의 정보를 포함하는 구조체로, 이를 통해 JavaScript로부터 데이터를 받을 수 있음.

  if (info.Length() != 1) {
    throw Napi::Error::New(info.Env(),
                           "Need one argument: a pointer to the Buffer object");
  }
  if (!info[0].IsBuffer()) { // 첫 번째 인자가 JavaScript의 Buffer 객체인지 확인. Buffer는 JavaScript에서 바이너리 데이터를 처리하는 객체
    throw Napi::Error::New(info.Env(), "Expected a Buffer");
  }

  // 인자를 Napi::Buffer로 변환하여 사용할 준비. 이 버퍼는 8비트 정수 배열로 처리.
  auto buf = info[0].As<Napi::Buffer<uint8_t>>();

  // JavaScript 버퍼 데이터를 gCoverageCounters에 저장. 이 포인터는 커버리지 카운터의 시작 위치를 가리킴.
  gCoverageCounters = reinterpret_cast<uint8_t *>(buf.Data());
  // Fill the PC table with fake entries. The only requirement is that the fake
  // addresses must not collide with the locations of real counters (e.g., from
  // instrumented C++ code). Therefore, we just use the address of the counter
  // itself - it's in a statically allocated memory region under our control.
  // // PC 테이블을 가짜 항목으로 채웁니다. 
  // 유일한 요구 사항은 가짜 주소가 실제 카운터의 위치(예: 도구가 삽입된 C++ 코드에서 사용되는 위치)와 충돌하지 않아야 한다는 것입니다. 
  // 따라서 우리는 단순히 카운터 자체의 주소를 사용합니다. 이 주소는 우리가 제어하는 정적으로 할당된 메모리 영역에 있습니다.

  gPCEntries = new PCTableEntry[buf.Length()];
  for (std::size_t i = 0; i < buf.Length(); ++i) {
    gPCEntries[i] = {i, 0};
  }
  
  // 커버리지 맵을 확인하고 싶을 때 호출할 수 있도록 PrintCoverageMap 추가
  for (std::size_t i = 0; i < buf.Length(); ++i) {
      std::cout << "Counter " << i << ": " << static_cast<int>(gCoverageCounters[i]) << std::endl;
  }

}


void RegisterNewCounters(const Napi::CallbackInfo &info) {
  if (info.Length() != 2) {
    throw Napi::Error::New(
        info.Env(), "Need two arguments: the old and new number of counters");
  }

  auto old_num_counters = info[0].As<Napi::Number>().Int64Value(); // 기존 카운터 수
  auto new_num_counters = info[1].As<Napi::Number>().Int64Value(); // 새로운 카운터 

  if (gCoverageCounters == nullptr) {
    throw Napi::Error::New(info.Env(),
                           "RegisterCoverageMap should have been called first");
  }
  if (new_num_counters < old_num_counters) {
    throw Napi::Error::New(
        info.Env(),
        "new_num_counters must not be smaller than old_num_counters");
  }
  if (new_num_counters == old_num_counters) {
    // 새로운 카운터 수가 기존과 동일하다면 더 이상 작업할 필요가 없으므로 함수는 종료
    return;
  }

// 새롭게 추가된 커버리지 카운터와 프로그램 카운터를 초기화. 이 부분은 LibFuzzer가 사용하는 Sanitizer Coverage를 통해 커버리지 수집을 가능하게 함.
  __sanitizer_cov_8bit_counters_init(gCoverageCounters + old_num_counters,
                                     gCoverageCounters + new_num_counters);
  __sanitizer_cov_pcs_init((uintptr_t *)(gPCEntries + old_num_counters),
                           (uintptr_t *)(gPCEntries + new_num_counters));
}
