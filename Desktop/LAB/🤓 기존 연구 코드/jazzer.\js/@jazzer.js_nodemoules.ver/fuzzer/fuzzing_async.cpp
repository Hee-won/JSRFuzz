// Copyright 2022 Code Intelligence GmbH
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
#include <future>
#include <iostream>

#ifdef _WIN32
#include <process.h>
#define GetPID _getpid
#else
#include <unistd.h>
#define GetPID getpid
#endif

#include "fuzzing_async.h"
#include "shared/libfuzzer.h"
#include "utils.h"

namespace {

// The context of the typed thread-safe function we use to call the JavaScript
// fuzz target. JavaScript fuzz 타겟을 호출하는 타입 스레드 안전 함수의 컨텍스트
struct AsyncFuzzTargetContext {
  explicit AsyncFuzzTargetContext(Napi::Env env)
      : deferred(Napi::Promise::Deferred::New(env)){};
  std::thread native_thread;
  Napi::Promise::Deferred deferred;
  bool is_resolved = false;
  bool is_done_called = false;
  AsyncFuzzTargetContext() = delete;
};

// The data type to use each time we schedule a call to the JavaScript fuzz
// target. It includes the fuzzer-generated input and a promise to await the
// execution of the JS fuzz target. The value with which the promise is
// resolved is forwarded to the fuzzer loop and controls if it should continue
// or stop.
// JavaScript 퍼징 대상을 호출할 때마다 사용할 데이터 타입입니다. 
// 이 타입에는 퍼저(fuzzer)가 생성한 입력과 JS 퍼징 대상의 실행을 기다리기 위한 Promise가 포함됩니다. 
// Promise가 해결된 값은 퍼저 루프로 전달되며, 퍼저 루프가 계속 실행할지 중단할지를 제어합니다.

struct DataType {
  const uint8_t *data;
  size_t size;
  std::promise<int> *promise;

  DataType() = delete;
};

void CallJsFuzzCallback(Napi::Env env, Napi::Function jsFuzzCallback,
                        AsyncFuzzTargetContext *context, DataType *data);
using TSFN = Napi::TypedThreadSafeFunction<AsyncFuzzTargetContext, DataType,
                                           CallJsFuzzCallback>;
using FinalizerDataType = void;

TSFN gTSFN;

const std::string SEGFAULT_ERROR_MESSAGE =
    "Segmentation fault found in fuzz target";

std::jmp_buf errorBuffer;

// See comment on `ErrorSignalHandler` in `fuzzing_sync.cpp` for what this is
// for
void ErrorSignalHandler(int signum) { std::longjmp(errorBuffer, signum); }

// The callback invoked by libFuzzer. It has no access to the JavaScript
// environment and thus can only call the JavaScript fuzz target via the
// typed thread-safe function.
// libFuzzer에 의해 호출되는 콜백입니다. 
// 이 콜백은 JavaScript 환경에 접근할 수 없으므로, 
// 타입이 지정된 스레드-안전 함수(typed thread-safe function)를 통해서만 JavaScript 퍼징 대상을 호출할 수 있습니다.
int FuzzCallbackAsync(const uint8_t *Data, size_t Size) {
  // Pass a promise to the addon part executed in the JavaScript context
  // via the data object of the typed thread-safe function. Await it's
  // resolution or rejection to continue fuzzing.
  // 타입이 지정된 스레드-안전 함수의 data 객체를 통해 JavaScript 컨텍스트에서 실행되는 애드온 부분에 Promise를 전달합니다.
  // Promise가 해결되거나 거부되기를 기다린 후 퍼징을 계속 진행합니다.

  std::promise<int> promise;
  auto input = DataType{Data, Size, &promise};

  auto future = promise.get_future();
  auto status = gTSFN.BlockingCall(&input);
  if (status != napi_ok) {
    Napi::Error::Fatal("FuzzCallbackAsync",
                       "Napi::TypedThreadSafeFunction.BlockingCall() failed");
  }
  try {
    // Await the return of the JavaScript fuzz target with
    // libfuzzer::RETURN_EXIT or libfuzzer::RETURN_CONTINUE.
    return future.get();
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
}

// This function is the callback that gets executed in the addon's main thread
// (i.e., the JavaScript event loop thread) and thus we can call the JavaScript
// code and use the Node API to create JavaScript objects.
// 이 함수는 애드온의 메인 스레드(즉, JavaScript 이벤트 루프 스레드)에서 실행되는 콜백입니다. 
// 따라서 이 함수에서 JavaScript 코드를 호출하고 Node API를 사용하여 JavaScript 객체를 생성할 수 있습니다.   
void CallJsFuzzCallback(Napi::Env env, Napi::Function jsFuzzCallback,
                      // env: 자바스크립트 환경을 나타내는 객체로, 자바스크립트와 C++ 간의 상호작용에 필요.
                      // jsFuzzCallback: 자바스크립트에서 전달된 퍼징 타겟 함수로, 데이터를 전달하고 호출될 함수.
                        AsyncFuzzTargetContext *context, DataType *data) {\
                      // *context: 현재 비동기 실행 상태를 저장하는 구조체로, 실행 상태 정보를 관리.
                      // *data: libFuzzer로부터 전달받은 데이터로, 퍼징 타겟에 전달되는 바이너리 입력 데이터를 포함함.

  // Execute the fuzz target and reject the deferred on any raised exception by
  // C++ code or returned error by JS interop to stop fuzzing.
  // 퍼징 대상을 실행하고 C++ 코드에서 발생한 예외나 JS 상호작용에서 반환된 오류에 대해 deferred를 거부하여 퍼징을 중지합니다.
  try {
    // Return point for the segfault error handler
    // This MUST BE called from the thread that executes the fuzz target (and
    // thus is the thread with the segfault) otherwise longjmp's behavior is
    // undefined
    // 세그폴트(segfault) 에러 핸들러의 반환 지점
    // 이 함수는 반드시 퍼징 대상을 실행하는 스레드(즉, 세그폴트가 발생한 스레드)에서 호출되어야 합니다. 
    // 그렇지 않으면 longjmp의 동작이 정의되지 않습니다.

    if (setjmp(errorBuffer) != 0) {
      std::cerr << "==" << (unsigned long)GetPID() << "== Segmentation Fault"
                << std::endl;
      libfuzzer::PrintCrashingInput();
      _Exit(libfuzzer::EXIT_ERROR_SEGV);
      // errorBuffer는 longjmp로 돌아갈 지점, setjmp/longjmp는 오류 복구에 사용됨.
    }
    if (env != nullptr) { // env != nullptr: 자바스크립트 환경이 유효한지 확인.

      // libFuzzer에서 전달된 바이너리 데이터를 자바스크립트로 변환하여 사용하도록 복사.
      auto buffer = Napi::Buffer<uint8_t>::Copy(env, data->data, data->size);

      // 자바스크립트에서 퍼징 타겟 함수가 몇 개의 매개변수를 요구하는지 확인.
      auto parameterCount = jsFuzzCallback.As<Napi::Object>()
                                .Get("length")
                                .As<Napi::Number>()
                                .Int32Value();

      // In case more than one parameter is expected, the second one is
      // considered to be a done callback to indicate finished execution.
      // 매개변수가 두 개 이상일 때, 두 번째 매개변수를 완료 콜백(done)으로 간주하여 퍼징이 완료되었음을 알림.
      if (parameterCount > 1) {
        context->is_done_called = false;
        context->is_resolved = false;
        auto done = // 자바스크립트 done 콜백 함수를 생성하여, 퍼징 완료를 나타내도록 설정.
            Napi::Function::New<>(env, [=](const Napi::CallbackInfo &info) {
              // If the done callback based fuzz target also returned a promise,
              // is_resolved could been set and there's nothing to do anymore.
              // As the done callback is executed on the main event loop, no
              // synchronization for is_resolved is needed.
              // done 콜백 기반의 퍼징 대상이 promise를 반환한 경우,
              // is_resolved가 설정될 수 있으며 더 이상 할 일이 없습니다.
              // done 콜백은 메인 이벤트 루프에서 실행되므로 is_resolved에 대한 동기화는 필요하지 않습니다.

              // 퍼징이 이미 완료된 경우 중복 처리를 방지하기 위해 함수 종료.
              if (context->is_resolved) {
                return;
              }

              // Raise an error if the done callback is called multiple times.
              // done 콜백이 여러 번 호출된 경우, 에러를 기록하고 퍼징을 종료.
              if (context->is_done_called) {
                context->deferred.Reject(
                    Napi::Error::New(env, "Expected done to be called once, "
                                          "but it was called multiple times.")
                        .Value());
                context->is_resolved = true;
                // Can not break out of the fuzzer loop, as the promise was
                // already resolved in the last invocation of the done
                // callback. Probably the best thing to do is print an error
                // message and await the timeout.
                std::cerr << "Expected done to be called once, but it was "
                             "called multiple times."
                          << std::endl;
                return;
              }

              // Mark if the done callback is invoked, to be able to check for
              // wrongly returned promises and multiple invocations.
              context->is_done_called = true;

              auto hasError = !(info[0].IsNull() || info[0].IsUndefined());
              if (hasError) { // done 콜백에서 에러가 전달되었는지 확인.
                data->promise->set_value(libfuzzer::RETURN_EXIT);
                context->deferred.Reject(info[0].As<Napi::Error>().Value());
                context->is_resolved = true;
              } else {
                data->promise->set_value(libfuzzer::RETURN_CONTINUE);
              }
            });
        auto result = jsFuzzCallback.Call({buffer, done});
        // 자바스크립트의 퍼징 타겟 함수를 호출하고, buffer와 done 콜백을 전달함.
        if (result.IsPromise()) {
          // If the fuzz target received a done callback, but also returned a
          // promise, the callback could already have been called. In that case
          // is_done_called is already set. If is_resolved is also set, the
          // callback was invoked with an error and already propagated that. If
          // not, an appropriate error, describing the illegal return value,
          // can be set. As everything is executed on the main event loop, no
          // synchronization is needed.
          AsyncReturnsHandler();
          if (context->is_resolved) {
            return;
          }
          if (!context->is_done_called) {
            data->promise->set_value(libfuzzer::RETURN_EXIT);
          }
          context->deferred.Reject(
              Napi::Error::New(env, "Internal fuzzer error - Either async or "
                                    "done callback based fuzz tests allowed.")
                  .Value());
          context->is_resolved = true;
        } else {
          SyncReturnsHandler();
        }
        return;
      }

      auto result = jsFuzzCallback.Call({buffer});

      // Register callbacks on returned promise to await its resolution before
      // resolving the fuzzer promise and continue fuzzing. Otherwise, resolve
      // and continue directly.
      if (result.IsPromise()) {
        AsyncReturnsHandler();
        auto jsPromise = result.As<Napi::Object>();
        auto then = jsPromise.Get("then").As<Napi::Function>();
        then.Call(
            jsPromise,
            {Napi::Function::New<>(env,
                                   [=](const Napi::CallbackInfo &info) {
                                     data->promise->set_value(
                                         libfuzzer::RETURN_CONTINUE);
                                   }),
             Napi::Function::New<>(env, [=](const Napi::CallbackInfo &info) {
               // This is the only way to pass an exception from JavaScript
               // through C++ back to calling JavaScript code.
               data->promise->set_value(libfuzzer::RETURN_EXIT);
               context->deferred.Reject(info[0].As<Napi::Error>().Value());
               context->is_resolved = true;
             })});
      } else {
        SyncReturnsHandler();
        data->promise->set_value(libfuzzer::RETURN_CONTINUE);
      }
    } else {
      data->promise->set_exception(std::make_exception_ptr(
          std::runtime_error("Environment is shut down")));
    }
  } catch (const Napi::Error &error) {
    // JS exception thrown by invocation of the fuzz target. This is an
    // unhandled exception in the tested code or a finding of a bug detector.
    if (context->is_resolved)
      return;
    data->promise->set_value(libfuzzer::RETURN_EXIT);
    context->deferred.Reject(error.Value());
    context->is_resolved = true;
  } catch (const std::exception &exception) {
    data->promise->set_value(libfuzzer::RETURN_EXIT);
    auto message =
        std::string("Internal fuzzer error - ").append(exception.what());
    context->deferred.Reject(Napi::Error::New(env, message).Value());
    context->is_resolved = true;
  }
}

} // namespace

// Start libfuzzer with a JS fuzz target asynchronously.
//
// This is a JS-enabled version of libfuzzer's main function (see FuzzerMain.cpp
// in the compiler-rt source). It takes the fuzz target, which must be a JS
// function taking a single data argument, as its first parameter; the fuzz
// target's return value is ignored. The second argument is an array of
// (command-line) arguments to pass to libfuzzer.
// 이것은 libfuzzer의 메인 함수의 JS 지원 버전입니다 (compiler-rt 소스의 FuzzerMain.cpp 참조). 
// 첫 번째 인수로는 단일 데이터 인수를 받는 JS 함수인 퍼징 대상이 제공되어야 하며, 퍼징 대상의 반환 값은 무시됩니다. 
// 두 번째 인수는 libfuzzer에 전달할 (명령줄) 인수 배열입니다.
//
// In order not to block JavaScript event loop, we start libfuzzer in a separate
// thread and use a typed thread-safe function to manage calls to the JavaScript
// fuzz target which can only happen in the addon's main thread. This function
// returns a promise so that the JavaScript code can use `catch()` to check when
// the promise is rejected.
// JavaScript 이벤트 루프를 차단하지 않기 위해 libfuzzer를 별도의 스레드에서 시작하고, 
// addon's 메인 스레드에서만 실행할 수 있는 JavaScript 퍼징 대상 호출을 관리하기 위해 타이핑된 스레드-안전한 함수를 사용합니다. 
// 이 함수는 Promise를 반환하여 JavaScript 코드에서 `catch()`를 사용해 Promise가 거부될 때 이를 확인할 수 있도록 합니다.

Napi::Value StartFuzzingAsync(const Napi::CallbackInfo &info) {
  if (info.Length() != 2 || !info[0].IsFunction() || !info[1].IsArray()) {
    throw Napi::Error::New(info.Env(),
                           "Need two arguments, which must be the fuzz target "
                           "function and an array of libfuzzer arguments");
  }

  // 첫 번째 인자(info[0])는 JavaScript의 함수이어야 합니다. 이 함수가 퍼징 타겟입니다.
  // 두 번째 인자(info[1])는 배열이어야 하며, 이 배열은 LibFuzzer에 전달될 인자들을 포함합니다.
  auto fuzz_target = info[0].As<Napi::Function>();
  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  // Store the JS fuzz target and corresponding environment, so that the C++
  // fuzz target can use them to call back into JS.
  // AsyncFuzzTargetContext 객체를 생성하여 비동기적으로 퍼징을 관리할 환경 정보를 저장합니다. 
  // 이 객체는 이후 퍼징 프로세스를 관리합니다.

  auto *context = new AsyncFuzzTargetContext(info.Env());

  // 퍼징 중 JavaScript 환경과 C++간의 안전한 비동기 호출을 관리
  gTSFN = TSFN::New( // Thread-Safe Function 
      info.Env(),         // Env
      fuzz_target,        // Callback
      "FuzzerAsyncAddon", // Name
      0,                  // Unlimited Queue 큐의 크기를 무제한으로 설정
      1,                  // Only one thread will use this initially
      context,            // Context object passed into the callback
      [](Napi::Env env, FinalizerDataType *, AsyncFuzzTargetContext *ctx) {
        // This finalizer is executed in the main event loop context and hence
        // has access to the JavaScript environment. The deferred is only
        // unresolved if no error was found during fuzzing.
        // TSFN이 해제될 때, C++ 스레드가 종료될 때 이 코드가 실행됩니다. 
        // ctx->native_thread.join()은 스레드를 동기화하며, 
        // 퍼징이 완료되지 않았다면 deferred.Resolve를 통해 JavaScript에서 이 작업이 완료되었음을 알립니다.
        ctx->native_thread.join();
        if (!ctx->is_resolved) {
          ctx->deferred.Resolve(env.Undefined());
        }
        delete ctx;
      });

  // Start libFuzzer in a separate thread to not block the JavaScript event loop.
  // 새로운 스레드를 생성하여 LibFuzzer를 비동기적으로 실행합니다. 
  // 이렇게 하면 JavaScript 이벤트 루프를 차단하지 않고도 퍼징을 진행할 수 있습니다.
  context->native_thread = std::thread(
      [](const std::vector<std::string> &fuzzer_args) {
        signal(SIGSEGV, ErrorSignalHandler);
        StartLibFuzzer(fuzzer_args, FuzzCallbackAsync);
        gTSFN.Release();
      },
      std::move(fuzzer_args));

  // Return promise to calling JS code to await fuzzing completion.
  // JavaScript 측에 Promise를 반환합니다. 이는 JavaScript 코드에서 퍼징 완료를 기다릴 수 있게 해줍니다.
  // deferred는 비동기 작업이 완료되었을 때 결과를 전달하는 데 사용됩니다.
  return context->deferred.Promise();
}
