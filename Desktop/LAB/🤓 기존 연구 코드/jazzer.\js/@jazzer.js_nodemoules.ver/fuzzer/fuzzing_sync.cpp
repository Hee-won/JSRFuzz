// Copyright 2023 Code Intelligence GmbH
//
//  Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
//  You may obtain a copy of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//  Unless required by applicable law or agreed to in writing, software
//  distributed under the License is distributed on an "AS IS" BASIS,
//  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
//  See the License for the specific language governing permissions and
//  limitations under the License.

#include "napi.h"
#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#ifdef _WIN32
#include <process.h>
#define GetPID _getpid
#else
#include <unistd.h>
#define GetPID getpid
#endif

#include "fuzzing_sync.h"
#include "shared/libfuzzer.h"
#include "utils.h"

namespace {
const std::string SEGFAULT_ERROR_MESSAGE =
    "Segmentation fault found in fuzz target";

// Information about a JS fuzz target.
struct FuzzTargetInfo { // Napi::Env, Napi::Function 등으로 JavaScript 퍼징 타겟의 정보를 저장
  Napi::Env env;
  Napi::Function target; 
  bool isResolved; // indicate if the deferred is resolved or not 해당 Promise가 완료되었는지
  Napi::Promise::Deferred deferred; // Promise를 나타냄
  Napi::Function jsStopCallback; // JS stop function used by signal handling.
};

// The JS fuzz target. We need to store the function pointer in a global
// variable because libfuzzer doesn't give us a way to feed user-provided data
// to its target function.
std::optional<FuzzTargetInfo> gFuzzTarget;

// Track if SIGINT signal handler was called.
// This is only necessary in the sync fuzzing case, as async can be handled
// much nicer directly in JavaScript.
volatile std::sig_atomic_t gSignalStatus; // gSignalStatus는 신호 핸들러에서 발생한 신호를 저장하는 전역 변수
std::jmp_buf errorBuffer; // longjmp와 setjmp를 사용하여 비동기 오류 복구를 위한 버퍼를 설정
} // namespace

void sigintHandler(int signum) { gSignalStatus = signum; }
//신호 핸들러: SIGINT 신호가 발생했을 때 호출되며, gSignalStatus에 신호 번호를 저장

// This handles signals that indicate an unrecoverable error (currently only
// segfaults). Our handling of segfaults is odd because it avoids using our
// Javascript method to print and instead prints a message within C++ and exits
// almost immediately. This is because Node seems to really not like being
// called back into after `longjmp` jumps outside the scope Node thinks it
// should be in and so things in JS-land get pretty broken. However, catching it
// here, printing an ok error message, and letting libfuzzer make the crash file
// is good enough
void ErrorSignalHandler(int signum) { // 에러 핸들러: SIGSEGV 같은 치명적인 신호가 발생했을 때 호출
  gSignalStatus = signum;
  std::longjmp(errorBuffer, signum); // longjmp를 사용해 에러 발생 시점으로 복귀
}

// The libFuzzer callback when fuzzing synchronously libfuzzer의 결과
int FuzzCallbackSync(const uint8_t *Data, size_t Size) { 
// Data와 Size는 libFuzzer가 전달한 입력 데이터와 그 크기
  // Create a new active scope so that handles for the buffer objects created in
  // this function will be associated with it. This makes sure that these
  // handles are only held live through the lifespan of this scope and gives
  // the garbage collector a chance to deallocate them between the fuzzer
  // iterations. Otherwise, new handles will be associated with the original
  // scope created by Node.js when calling StartFuzzing. The lifespan for this
  // default scope is tied to the lifespan of the native method call. The result
  // is that, by default, handles remain valid and the objects associated with
  // these handles will be held live for the lifespan of the native method call.
  // This would exhaust memory resources since we run in an endless fuzzing loop
  // and only return when a bug is found. See:
  // https://github.com/nodejs/node-addon-api/blob/35b65712c26a49285cdbe2b4d04e25a5eccbe719/doc/object_lifetime_management.md
  auto scope = Napi::HandleScope(gFuzzTarget->env); // JavaScript 객체의 메모리 관리를 위한 범위를 지정

  try {
    // TODO Do we really want to copy the data? The user isn't allowed to
    // modify it (else the fuzzer will abort); moreover, we don't know when
    // the JS buffer is going to be garbage-collected. But it would still be
    // nice for efficiency if we could use a pointer instead of copying.
    // LibFuzzer로부터 전달받은 데이터를 JavaScript로 넘기기 위해 Napi::Buffer 객체로 복사
    auto data = Napi::Buffer<uint8_t>::Copy(gFuzzTarget->env, Data, Size);
    // 입력 데이터 처리: Napi::Buffer를 사용해 libFuzzer의 입력 데이터를 JavaScript로 전달
    
    if (setjmp(errorBuffer) == 0) {
      // 변환된 데이터를 JavaScript 타겟 함수에 전달하여 호출
      auto result = gFuzzTarget->target.Call({data});

      // Promise를 반환하는지 여부에 따라 결과 처리
      if (result.IsPromise()) {
        AsyncReturnsHandler();
      } else {
        SyncReturnsHandler();
      }
    }
  } catch (const Napi::Error &error) {
    // 예외 처리
    // Received a JS error indicating that the fuzzer loop should be stopped,
    // propagate it to the calling JS code via the deferred.
    gFuzzTarget->isResolved = true;
    gFuzzTarget->deferred.Reject(error.Value());
    return libfuzzer::RETURN_EXIT;
  } catch (std::exception &exception) {
    // Something in the interop did not work. Just call exit to immediately
    // terminate the process without performing any cleanup including libFuzzer
    // exit handlers.
    std::cerr << "==" << (unsigned long)GetPID()
              << "== Jazzer.js: Unexpected Error: " << exception.what()
              << std::endl;
    libfuzzer::PrintCrashingInput();
    _Exit(libfuzzer::EXIT_ERROR_CODE);
  }

  if (gSignalStatus != 0) {
    // if we caught a segfault, print the error message and die
    if (gSignalStatus == SIGSEGV) {
      std::cerr << "==" << (unsigned long)GetPID() << "== Segmentation Fault"
                << std::endl;
      libfuzzer::PrintCrashingInput();
      _Exit(libfuzzer::EXIT_ERROR_SEGV);
    }

    // Non-zero exit codes will produce crash files.
    auto exitCode = Napi::Number::New(gFuzzTarget->env, 0);

    if (gSignalStatus != SIGINT) {
      exitCode = Napi::Number::New(gFuzzTarget->env, gSignalStatus);
    }

    // Execute the signal handler in context of the node application.
    gFuzzTarget->jsStopCallback.Call({exitCode});
  }

  return libfuzzer::RETURN_CONTINUE;
}

// Start libfuzzer with a JS fuzz target.
//
// This is a JS-enabled version of libfuzzer's main function (see
// FuzzerMain.cpp in the compiler-rt source). It takes the fuzz target, which
// must be a JS function taking a single data argument, as its first
// parameter; the fuzz target's return value is ignored. The second argument
// is an array of (command-line) arguments to pass to libfuzzer.
// Napi::CallbackInfo 객체를 통해 JavaScript에서 전달된 3개의 인자를 받아 libFuzzer를 시작
Napi::Value StartFuzzing(const Napi::CallbackInfo &info) {
  // 첫 번째 인자는 퍼징 타겟 함수, 두 번째 인자는 libFuzzer 명령줄 인수 배열, 세 번째 인자는 종료 시 콜백 함수
  if (info.Length() != 3 || !info[0].IsFunction() || !info[1].IsArray() ||
      !info[2].IsFunction()) {
    throw Napi::Error::New(
        info.Env(),
        "Need three arguments, which must be the fuzz target "
        "function, an array of libfuzzer arguments, and a callback function "
        "that the fuzzer will call in case of SIGINT or a segmentation fault");
  }

  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  // Store the JS fuzz target and corresponding environment globally, so that
  // our C++ fuzz target can use them to call back into JS. Also store the stop
  // function that will be called in case of a SIGINT/SIGSEGV.
  gFuzzTarget = {info.Env(), info[0].As<Napi::Function>(), false,
                 Napi::Promise::Deferred::New(info.Env()),
                 info[2].As<Napi::Function>()};

  signal(SIGINT, sigintHandler);
  signal(SIGSEGV, ErrorSignalHandler);

  StartLibFuzzer(fuzzer_args, FuzzCallbackSync);

  // Resolve the deferred in case no error could be found during fuzzing.
  if (!gFuzzTarget->isResolved) {
    gFuzzTarget->deferred.Resolve(gFuzzTarget->env.Undefined());
  }
  // Return a promise potentially containing a found error.
  return gFuzzTarget->deferred.Promise();
}
