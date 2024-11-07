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

#include <iostream>

#include "fuzzing_async.h"
#include "fuzzing_sync.h"

#include "shared/callbacks.h"
#include "shared/libfuzzer.h"
#include "utils.h"

// Print and dump the current input. This function is called during a fuzzing
// run when a finding is detected, afterwards the fuzzer loop is stopped via
// the appropriate callback return value.
// 퍼징 도중 오류가 발생했을 때(예: 크래시가 발생했을 때) 해당 입력을 출력하고 덤프
void PrintAndDumpCrashingInput(const Napi::CallbackInfo &info) {
  libfuzzer::PrintCrashingInput(); 
  // libfuzzer::PrintCrashingInput() 함수를 통해 LibFuzzer가 크래시한 입력 데이터를 기록
}

// Print info messages recommending invocation improvements (sync/async).
// 퍼징 실행 중 동기적 또는 비동기적 실행의 결과에 대해 성공적인지 추가 정보를 출력. 
void PrintReturnInfo(const Napi::CallbackInfo &info) {
  if (info.Length() != 1 || !info[0].IsBoolean()) {
    throw Napi::Error::New(info.Env(), "Need one boolean argument");
  }
  PrintReturnValueInfo(info[0].ToBoolean());
}

// A basic sanity check: ask the Node API for version information and print it.
// 현재 사용 중인 Node.js 버전과 Node-API 버전을 출력
void PrintVersion(const Napi::CallbackInfo &info) {
  auto napi_version = Napi::VersionManagement::GetNapiVersion(info.Env());
  auto node_version = Napi::VersionManagement::GetNodeVersion(info.Env());
  std::cout << "Jazzer.js running on Node " << node_version->major
            << " using Node-API version " << napi_version << std::endl;
}

// This code is defining a function called "Init" which is used to initialize a
// Node.js addon module. The function takes two arguments, an "env" object, and
// an "exports" object.
// The "exports" object is an instance of the `Napi::Object` class, which is
// used to define the exports of the Node.js addon module. The code is adding
// properties to the "exports" object, where each property is a JavaScript
// function that corresponds to a C++ function.
// `RegisterCallbackExports` links more functions needed, like coverage tracking
// capabilities.
// 이 코드는 "Init"이라는 함수를 정의하고 있으며, 이는 Node.js 애드온 모듈을 초기화하는 데 사용됩니다. 이 함수는 두 개의 인수, "env" 객체와 "exports" 객체를 받습니다.  
// "exports" 객체는 `Napi::Object` 클래스의 인스턴스로, Node.js 애드온 모듈의 exports를 정의하는 데 사용됩니다.  
// 이 코드는 "exports" 객체에 속성을 추가하며, 각 속성은 C++ 함수와 연결된 JavaScript 함수입니다.  
// `RegisterCallbackExports`는 커버리지 추적 기능과 같은 더 많은 필요한 함수들을 연결합니다.


// Node.js와 C++ 애드온을 연결하는 초기화 함수, JavaScript에서! 사용할 jazzer.js의 C++ 함수를 등록하고 내보내는 역할
Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports["printAndDumpCrashingInput"] =
      Napi::Function::New<PrintAndDumpCrashingInput>(env);
  exports["printReturnInfo"] = Napi::Function::New<PrintReturnInfo>(env);
  exports["printVersion"] = Napi::Function::New<PrintVersion>(env);
  
  // 이 함수는 퍼징을 시작하는 기능을 수행
  exports["startFuzzing"] = Napi::Function::New<StartFuzzing>(env);
  // 비동기 퍼징을 시작합니다. 비동기적으로 실행되므로 Node.js의 이벤트 루프와 함께 동작하며, 퍼징이 완료되기 전까지 다른 작업을 계속 수행할 수 있음.
  exports["startFuzzingAsync"] = Napi::Function::New<StartFuzzingAsync>(env);

  RegisterCallbackExports(env, exports);
  return exports;
}

// Macro that exports the "Init" function as the entry point of the addon module
// named "myPackage". When this addon is imported in a Node.js script, the
// "Init" function will be executed to define the exports of the addon.
// This effectively allows us to do this from the Node.js side of things:
// const jazzerjs = require('jazzerjs');
// jazzerjs.printVersion
// Node.js 모듈을 생성하는 데 사용되며, Init 함수가 모듈의 진입점으로 등록됨.
NODE_API_MODULE(jazzerjs, Init)
