#include <csetjmp>
#include <vector>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <optional>
#include <sstream>
#include <fstream>  // 추가: 파일 입출력 관련 타입을 위해 필요
#include <vector>   // 추가: std::vector를 사용하기 위해 필요
#include <string>   // 추가: std::string을 사용하기 위해 필요
#include <filesystem>  // 파일 시스템 조작을 위한 라이브러리
#include <cmath>
#include <algorithm>
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

// 텍스트 파일을 읽어와 문자열 배열로 변환하는 함수
std::vector<std::string> ReadStringsFromFile(const std::string& filePath) {
    std::vector<std::string> strings;
    std::ifstream inputFile(filePath);
    std::string line;

    while (std::getline(inputFile, line)) {
        strings.push_back(line);  // 각 줄을 배열에 추가
    }

    inputFile.close();
    return strings;
}


int ExtractSeaOfNodes(const std::string& inputData, const std::string& seaOfNodesFile) {
    std::cout << "ExtractSeaOfNodes is being executed!" << std::endl;

    // 파일로 fuzzData 저장
    std::string fuzzDataFile = "./fuzz_data/fuzz_data_" + std::to_string(rand());
    std::ofstream outfile(fuzzDataFile, std::ios::binary);
    outfile.write(inputData.c_str(), inputData.size());
    outfile.close();

    // names.txt 파일에서 함수 이름들 읽기
    std::ifstream namesFile("names.txt");
    std::vector<std::string> functionNames;
    std::string funcName;
    while (std::getline(namesFile, funcName)) {
        functionNames.push_back(funcName);
    }
    namesFile.close();

    std::ofstream executedFuncsFile("executed_func_lists.txt", std::ios::app); // 결과를 저장할 파일
    std::string result;
    for (const auto& func : functionNames) {
        std::string command = "/home/heewon/node/node-16.19.0/out/Release/node --always-opt --trace-turbo-graph --turbo-filter=" + func + " ./fuzzTarget_for_SoN.js " + fuzzDataFile + " > " + seaOfNodesFile;
        std::cout << "<<ExtractSeaOfNodes>> func :" << func << std::endl;

        // 서브프로세스 실행
        std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            std::cerr << "Failed to start subprocess for Sea of Nodes" << std::endl;
            return -1;
        }

        char buffer[128];
        std::ostringstream output;
        while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
            output << buffer;
        }

        // 명령어 결과 확인
        result = output.str();
        if (result != "Concurrent recompilation has been disabled for tracing.\n") {
            executedFuncsFile << func << std::endl;
            std::cout << "Function " << func << " stored in executed_func_lists.txt" << std::endl;
        } else {
            std::cout << "Ignoring function: " << func << " (No significant output)." << std::endl;
        }
    }

    executedFuncsFile.close();
    return 0;
}


void CalculateAndStoreDistanceValueWithEntropy(const std::string& distanceCsvFile, const std::string& executedFuncsFile) {
    std::cout << "CalculateAndStoreDistanceValueWithEntropy is being executed!" << std::endl;
    std::ifstream distanceCsv(distanceCsvFile);
    std::ifstream executedFuncs(executedFuncsFile);
    std::ofstream resultFile("distance_value_for_entropic.txt");

    if (!distanceCsv.is_open() || !executedFuncs.is_open()) {
        std::cerr << "Error opening distance.csv or executed_func_lists.txt file." << std::endl;
        return;
    }

    std::string line;
    std::vector<std::string> executedFuncNames;

    // 실행된 함수 이름을 벡터에 저장
    while (std::getline(executedFuncs, line)) {
        executedFuncNames.push_back(line);
    }

    // 거리값을 저장할 벡터
    std::vector<float> distances;

    // distance.csv 파일을 읽고 함수 이름이 일치하면 거리값을 저장
    while (std::getline(distanceCsv, line)) {
        std::stringstream ss(line);
        std::string funcName;
        std::string distanceStr;
        std::getline(ss, funcName, ',');
        std::getline(ss, distanceStr, ',');

        // 실행된 함수 목록과 일치하는 함수 이름이 있는지 확인
        if (std::find(executedFuncNames.begin(), executedFuncNames.end(), funcName) != executedFuncNames.end()) {
            float distanceValue = std::stof(distanceStr);  // 문자열을 float로 변환
            distances.push_back(distanceValue);
            std::cout << "Found matching function: " << funcName << ", Distance: " << distanceValue << std::endl;
        }
    }

    // 두 번째 방법: 지수 함수 적용
    float alpha = 1.0f;  // 스케일링 파라미터
    float totalWeight_exp = 0.0f;

    for (float d : distances) {
        float weight_exp = std::exp(-alpha * d);  // 가중치 계산
        totalWeight_exp += weight_exp;  // 총 가중치 누적
    }

    // 결과 파일에 가중치 저장 (숫자 값만 출력)
    resultFile << totalWeight_exp << std::endl;

    // 콘솔에 결과 출력 (숫자 값만 출력)
    std::cout << "totalWeight_exp " << totalWeight_exp << std::endl;

    distanceCsv.close();
    executedFuncs.close();
    resultFile.close();
}


// 타겟 함수들이 실행된 함수들에 모두 있는지 확인
bool AreTargetFunctionsExecuted(const std::string& executedFuncsFile, const std::string& targetFuncsFile) {
    std::cout << "AreTargetFunctionsExecuted is being executed!" << std::endl;
    std::vector<std::string> executedFuncs = ReadStringsFromFile(executedFuncsFile);
    std::vector<std::string> targetFuncs = ReadStringsFromFile(targetFuncsFile);

    bool allFound = true;

    for (const auto& target : targetFuncs) {
        // 각 타겟 함수가 실행된 함수 목록에 있는지 확인
        if (std::find(executedFuncs.begin(), executedFuncs.end(), target) != executedFuncs.end()) {
            std::cout << "Found target function: " << target << std::endl;
        } else {
            std::cout << "Did not find target function: " << target << std::endl;
            allFound = false;  // 하나라도 찾지 못하면 false로 변경
        }
    }

    return allFound;  // 모든 타겟 함수가 실행된 함수 목록에 있으면 true, 아니면 false
}

// Sea of Nodes 파일 이름에 'reachable'을 추가하는 함수
void AddReachableToFileName(std::string& seaOfNodesFile) {
    size_t extensionPos = seaOfNodesFile.find_last_of(".");
    if (extensionPos != std::string::npos) {
        seaOfNodesFile.insert(extensionPos, "_reachable");
    } else {
        seaOfNodesFile += "_reachable";
    }
    std::rename(seaOfNodesFile.c_str(), seaOfNodesFile.c_str());  // 파일 이름 변경
}

// The libFuzzer callback when fuzzing synchronously libfuzzer의 결과
int FuzzCallbackSync(const uint8_t *Data, size_t Size) { 
  std::cout << "FuzzCallbackSync is being executed!" << std::endl;  // 로그 출력
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
// 새로운 활성 스코프를 생성하여 이 함수에서 생성된 버퍼 객체의 핸들이 이 스코프와 연관되도록 합니다. 
// 이를 통해 이러한 핸들이 이 스코프의 수명 동안에만 활성 상태로 유지되며, 퍼저의 반복 사이에서 
// 가비지 컬렉터가 이를 해제할 기회를 갖도록 합니다. 그렇지 않으면 새로운 핸들이 Node.js가 
// StartFuzzing을 호출할 때 생성된 기본 스코프와 연관됩니다. 이 기본 스코프의 수명은 
// 네이티브 메서드 호출의 수명에 묶여 있습니다. 기본적으로는 핸들이 유효하게 남아 있으며, 
// 이 핸들과 연관된 객체들은 네이티브 메서드 호출의 수명 동안 계속 유지됩니다.
// 우리는 끝없이 퍼징 루프를 실행하고 버그가 발견될 때에만 반환되기 때문에, 메모리 자원이 소진될 수 있습니다.

  auto scope = Napi::HandleScope(gFuzzTarget->env); // JavaScript 객체의 메모리 관리를 위한 범위를 지정

  /*
  INPUT 설명
  - executed_func_lists.txt: SoN에서 발견한 실제 실행된 함수 리스트
  - target_func_lists.txt: 내가 reachable을 조사하고 싶은 함수명
  - distance.csv: 거리값이 계산된 파일
  - distance_value_for_entropic.txt: 거리값의 총합
  - names.txt: 함수 이름들만 있는 파
  */

  try {
    // TODO Do we really want to copy the data? The user isn't allowed to
    // modify it (else the fuzzer will abort); moreover, we don't know when
    // the JS buffer is going to be garbage-collected. But it would still be
    // nice for efficiency if we could use a pointer instead of copying.
    // LibFuzzer로부터 전달받은 데이터를 JavaScript로 넘기기 위해 Napi::Buffer 객체로 복사
    auto data = Napi::Buffer<uint8_t>::Copy(gFuzzTarget->env, Data, Size);
    // 입력 데이터 처리: Napi::Buffer를 사용해 libFuzzer의 입력 데이터를 JavaScript로 전달

    std::string seaOfNodesFile = "./SoN/sea_of_nodes_" + std::to_string(rand()) + ".txt";

        // Sea of Nodes 추출 및 저장
        if (ExtractSeaOfNodes(std::string(reinterpret_cast<const char*>(Data), Size), seaOfNodesFile) != 0) {
            std::cerr << "Failed to extract Sea of Nodes" << std::endl;
            return libfuzzer::RETURN_CONTINUE;
        }

        // 2. target_func_lists.txt가 executed_func_lists.txt에 있는지 확인
        if (AreTargetFunctionsExecuted("executed_func_lists.txt", "target_func_lists.txt")) {
            // 타겟 함수가 실행된 함수에 있으면 Sea of Nodes 파일 이름에 'reachable' 추가
            AddReachableToFileName(seaOfNodesFile);
        }

    // 여기서 distance.csv 파일을 읽고 거리를 계산한 후 저장
    CalculateAndStoreDistanceValueWithEntropy("distance.csv", "executed_func_lists.txt");


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

