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

// fuzzing_sync.cpp 파일 상단에 추가
extern uint8_t* gCoverageCounters;
const std::size_t MAX_COUNTERS = 1024; // 미리 설정된 최대 카운터 수

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


std::optional<FuzzTargetInfo> gFuzzTarget;


volatile std::sig_atomic_t gSignalStatus; // gSignalStatus는 신호 핸들러에서 발생한 신호를 저장하는 전역 변수
std::jmp_buf errorBuffer; // longjmp와 setjmp를 사용하여 비동기 오류 복구를 위한 버퍼를 설정
} // namespace

void sigintHandler(int signum) { gSignalStatus = signum; }
//신호 핸들러: SIGINT 신호가 발생했을 때 호출되며, gSignalStatus에 신호 번호를 저장


void ErrorSignalHandler(int signum) { // 에러 핸들러: SIGSEGV 같은 치명적인 신호가 발생했을 때 호출
  gSignalStatus = signum;
  std::longjmp(errorBuffer, signum); // longjmp를 사용해 에러 발생 시점으로 복귀
}

int FuzzCallbackSync(const uint8_t *Data, size_t Size) { 
  auto scope = Napi::HandleScope(gFuzzTarget->env); // JavaScript 객체의 메모리 관리를 위한 범위를 지정

  try {
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
    gFuzzTarget->isResolved = true;
    gFuzzTarget->deferred.Reject(error.Value());
    return libfuzzer::RETURN_EXIT;
  } catch (std::exception &exception) {

    std::cerr << "==" << (unsigned long)GetPID()
              << "== Jazzer.js: Unexpected Error: " << exception.what()
              << std::endl;
    libfuzzer::PrintCrashingInput();
    _Exit(libfuzzer::EXIT_ERROR_CODE);
  }

    // 현재 커버리지 맵 출력 추가
    std::cout << "++++++++++++++++++++++++=Current Coverage Map:" << std::endl;
    for (std::size_t i = 0; i < MAX_COUNTERS; ++i) {
        if (gCoverageCounters[i] != 0) { // 값이 0이 아닌 경우에만 출력
            std::cout << "Counter " << i << ": " << static_cast<int>(gCoverageCounters[i]) << std::endl;
        }
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

Napi::Value StartFuzzing(const Napi::CallbackInfo &info) {
  if (info.Length() != 3 || !info[0].IsFunction() || !info[1].IsArray() ||
      !info[2].IsFunction()) {
    throw Napi::Error::New(
        info.Env(),
        "Need three arguments, which must be the fuzz target "
        "function, an array of libfuzzer arguments, and a callback function "
        "that the fuzzer will call in case of SIGINT or a segmentation fault");
  }

  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  gFuzzTarget = {info.Env(), info[0].As<Napi::Function>(), false,
                 Napi::Promise::Deferred::New(info.Env()),
                 info[2].As<Napi::Function>()};

  signal(SIGINT, sigintHandler);
  signal(SIGSEGV, ErrorSignalHandler);

  StartLibFuzzer(fuzzer_args, FuzzCallbackSync);

  if (!gFuzzTarget->isResolved) {
    gFuzzTarget->deferred.Resolve(gFuzzTarget->env.Undefined());
  }
  // Return a promise potentially containing a found error.
  return gFuzzTarget->deferred.Promise();
}