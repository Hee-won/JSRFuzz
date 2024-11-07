#include "napi.h"
#include <csetjmp>
#include <csignal>
#include <cstdlib>
#include <future>
#include <iostream>
#include <fstream>      // For file I/O
#include <vector>       // For std::vector
#include <string>       // For std::string
#include <filesystem>   // For filesystem operations
#include <cmath>        // For mathematical functions
#include <algorithm>    // For std::find
#include <atomic>       // For std::atomic
#include <mutex>        // For std::mutex

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
// fuzzer 생성 입력과 JS fuzz 타겟 실행을 기다리는 프라미스 포함 데이터 타입.
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

// Signal handler for segmentation faults
void ErrorSignalHandler(int signum) { std::longjmp(errorBuffer, signum); }

// Atomic counter for unique file names (thread-safe)
static std::atomic<int> fileCounter(0);

// Helper functions

// Reads strings from a file into a vector
std::vector<std::string> ReadStringsFromFile(const std::string &filePath) {
  std::vector<std::string> strings;
  std::ifstream inputFile(filePath);
  std::string line;

  while (std::getline(inputFile, line)) {
    strings.push_back(line);
  }

  inputFile.close();
  return strings;
}

// Extracts Sea of Nodes from input data
int ExtractSeaOfNodes(const std::string &inputData,
                      const std::string &seaOfNodesFile, int fileCounter) {
  std::cout << "ExtractSeaOfNodes is being executed!" << std::endl;

  // Save fuzzData to a file
  std::string fuzzDataFile =
      "./fuzz_data/fuzz_data_" + std::to_string(fileCounter);
  std::ofstream outfile(fuzzDataFile, std::ios::binary);
  outfile.write(inputData.c_str(), inputData.size());
  outfile.close();

  // Read function names from names.txt
  std::ifstream namesFile("names.txt");
  std::vector<std::string> functionNames;
  std::string funcName;
  while (std::getline(namesFile, funcName)) {
    functionNames.push_back(funcName);
  }
  namesFile.close();

  std::ofstream executedFuncsFile(
      "executed_func_lists.txt",
      std::ios::app); // Append results to the output file
  std::string result;
  for (const auto &func : functionNames) {
    std::string command = "/home/heewon/node/node-16.19.0/out/Release/node "
                          "--always-opt --trace-turbo-graph --turbo-filter=" +
                          func + " ./fuzzTarget_for_SoN.js " + fuzzDataFile +
                          " > " + seaOfNodesFile;
    std::cout << "<<ExtractSeaOfNodes>> func :" << func << std::endl;

    // Execute subprocess
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(command.c_str(), "r"),
                                                  pclose);
    if (!pipe) {
      std::cerr << "Failed to start subprocess for Sea of Nodes" << std::endl;
      return -1;
    }

    char buffer[128];
    std::ostringstream output;
    while (fgets(buffer, sizeof(buffer), pipe.get()) != nullptr) {
      output << buffer;
    }

    // Check command result
    result = output.str();
    if (result !=
        "Concurrent recompilation has been disabled for tracing.\n") {
      executedFuncsFile << func << std::endl;
      std::cout << "Function " << func << " stored in executed_func_lists.txt"
                << std::endl;
    } else {
      std::cout << "Ignoring function: " << func << " (No significant output)."
                << std::endl;
    }
  }

  executedFuncsFile.close();
  return 0;
}

// Calculates and stores distance values with entropy
void CalculateAndStoreDistanceValueWithEntropy(
    const std::string &distanceCsvFile, const std::string &executedFuncsFile) {
  std::cout << "CalculateAndStoreDistanceValueWithEntropy is being executed!"
            << std::endl;
  std::ifstream distanceCsv(distanceCsvFile);
  std::ifstream executedFuncs(executedFuncsFile);
  std::ofstream resultFile("distance_value_for_entropic.txt");

  if (!distanceCsv.is_open() || !executedFuncs.is_open()) {
    std::cerr << "Error opening distance.csv or executed_func_lists.txt file."
              << std::endl;
    return;
  }

  std::string line;
  std::vector<std::string> executedFuncNames;

  // Store executed function names in a vector
  while (std::getline(executedFuncs, line)) {
    executedFuncNames.push_back(line);
  }

  // Vector to store distance values
  std::vector<float> distances;

  // Read distance.csv and store matching distance values
  while (std::getline(distanceCsv, line)) {
    std::stringstream ss(line);
    std::string funcName;
    std::string distanceStr;
    std::getline(ss, funcName, ',');
    std::getline(ss, distanceStr, ',');

    // Check if function name matches executed functions
    if (std::find(executedFuncNames.begin(), executedFuncNames.end(),
                  funcName) != executedFuncNames.end()) {
      float distanceValue = std::stof(distanceStr);
      distances.push_back(distanceValue);
      std::cout << "Found matching function: " << funcName
                << ", Distance: " << distanceValue << std::endl;
    }
  }

  // Calculate exponential weights
  float alpha = 1.0f;
  float totalWeight_exp = 0.0f;

  for (float d : distances) {
    float weight_exp = std::exp(-alpha * d);
    totalWeight_exp += weight_exp;
  }

  // Store the total weight
  resultFile << totalWeight_exp << std::endl;
  std::cout << "totalWeight_exp " << totalWeight_exp << std::endl;

  distanceCsv.close();
  executedFuncs.close();
  resultFile.close();
}

// Checks if target functions are executed
bool AreTargetFunctionsExecuted(const std::string &executedFuncsFile,
                                const std::string &targetFuncsFile) {
  std::cout << "AreTargetFunctionsExecuted is being executed!" << std::endl;
  std::vector<std::string> executedFuncs = ReadStringsFromFile(executedFuncsFile);
  std::vector<std::string> targetFuncs = ReadStringsFromFile(targetFuncsFile);

  bool allFound = true;

  for (const auto &target : targetFuncs) {
    if (std::find(executedFuncs.begin(), executedFuncs.end(), target) !=
        executedFuncs.end()) {
      std::cout << "Found target function: " << target << std::endl;
    } else {
      std::cout << "Did not find target function: " << target << std::endl;
      allFound = false;
    }
  }

  return allFound;
}

// Adds 'reachable' to the Sea of Nodes file name
void AddReachableToFileName(std::string &seaOfNodesFile) {
  size_t extensionPos = seaOfNodesFile.find_last_of(".");
  if (extensionPos != std::string::npos) {
    seaOfNodesFile.insert(extensionPos, "_reachable");
  } else {
    seaOfNodesFile += "_reachable";
  }
  std::rename(seaOfNodesFile.c_str(), seaOfNodesFile.c_str());
}

// The libFuzzer callback when fuzzing asynchronously
int FuzzCallbackAsync(const uint8_t *Data, size_t Size) {
  std::cout << "FuzzCallbackAsync is being executed!" << std::endl;

  // Atomic counter for unique file names
  int counter = fileCounter.fetch_add(1);

  try {
    // Process the input data before calling the JS fuzz target

    std::string seaOfNodesFile =
        "./SoN/sea_of_nodes_" + std::to_string(counter) + ".txt";

    // Extract Sea of Nodes
    if (ExtractSeaOfNodes(std::string(reinterpret_cast<const char *>(Data), Size),
                          seaOfNodesFile, counter) != 0) {
      std::cerr << "Failed to extract Sea of Nodes" << std::endl;
      return libfuzzer::RETURN_CONTINUE;
    }

    // Check if target functions are executed
    if (AreTargetFunctionsExecuted("executed_func_lists.txt",
                                   "target_func_lists.txt")) {
      // Modify Sea of Nodes file name to include 'reachable'
      AddReachableToFileName(seaOfNodesFile);
    }

    // Calculate distance values
    CalculateAndStoreDistanceValueWithEntropy("distance.csv",
                                              "executed_func_lists.txt");

    // Proceed with existing code to call the JS fuzz target
    std::promise<int> promise;
    auto input = DataType{Data, Size, &promise};

    auto future = promise.get_future();
    auto status = gTSFN.BlockingCall(&input);
    if (status != napi_ok) {
      Napi::Error::Fatal(
          "FuzzCallbackAsync",
          "Napi::TypedThreadSafeFunction.BlockingCall() failed");
    }
    try {
      // Await the return of the JavaScript fuzz target
      return future.get();
    } catch (std::exception &exception) {
      // Handle exceptions from future.get()
      std::cerr << "==" << (unsigned long)GetPID()
                << "== Jazzer.js: Unexpected Error: " << exception.what()
                << std::endl;
      libfuzzer::PrintCrashingInput();
      _Exit(libfuzzer::EXIT_ERROR_CODE);
    }
  } catch (const std::exception &e) {
    // Handle exceptions in our code
    std::cerr << "==" << (unsigned long)GetPID()
              << "== Exception in FuzzCallbackAsync: " << e.what() << std::endl;
    libfuzzer::PrintCrashingInput();
    _Exit(libfuzzer::EXIT_ERROR_CODE);
  }

  return libfuzzer::RETURN_CONTINUE;
}

// This function is the callback that gets executed in the addon's main thread
// (i.e., the JavaScript event loop thread) and thus we can call the JavaScript
// code and use the Node API to create JavaScript objects.
void CallJsFuzzCallback(Napi::Env env, Napi::Function jsFuzzCallback,
                        AsyncFuzzTargetContext *context, DataType *data) {
  // Execute the fuzz target and reject the deferred on any raised exception by
  // C++ code or returned error by JS interop to stop fuzzing.
  try {
    // Return point for the segfault error handler
    if (setjmp(errorBuffer) != 0) {
      std::cerr << "==" << (unsigned long)GetPID() << "== Segmentation Fault"
                << std::endl;
      libfuzzer::PrintCrashingInput();
      _Exit(libfuzzer::EXIT_ERROR_SEGV);
    }
    if (env != nullptr) {
      auto buffer = Napi::Buffer<uint8_t>::Copy(env, data->data, data->size);

      auto parameterCount = jsFuzzCallback.As<Napi::Object>()
                                .Get("length")
                                .As<Napi::Number>()
                                .Int32Value();
      // In case more than one parameter is expected, the second one is
      // considered to be a done callback to indicate finished execution.
      if (parameterCount > 1) {
        context->is_done_called = false;
        context->is_resolved = false;
        auto done =
            Napi::Function::New(env, [=](const Napi::CallbackInfo &info) {
              if (context->is_resolved)
                return;

              if (context->is_done_called) {
                context->deferred.Reject(
                    Napi::Error::New(
                        env, "Expected done to be called once, but it was called multiple times.")
                        .Value());
                context->is_resolved = true;
                std::cerr << "Expected done to be called once, but it was called multiple times."
                          << std::endl;
                return;
              }

              context->is_done_called = true;

              auto hasError = !(info[0].IsNull() || info[0].IsUndefined());
              if (hasError) {
                data->promise->set_value(libfuzzer::RETURN_EXIT);
                context->deferred.Reject(info[0].As<Napi::Error>().Value());
                context->is_resolved = true;
              } else {
                data->promise->set_value(libfuzzer::RETURN_CONTINUE);
              }
            });
        auto result = jsFuzzCallback.Call({buffer, done});
        if (result.IsPromise()) {
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
            {Napi::Function::New(env, [=](const Napi::CallbackInfo &info) {
               data->promise->set_value(libfuzzer::RETURN_CONTINUE);
             }),
             Napi::Function::New(env, [=](const Napi::CallbackInfo &info) {
               data->promise->set_value(libfuzzer::RETURN_EXIT);
               context->deferred.Reject(info[0].As<Napi::Error>().Value());
               context->is_resolved = true;
             })});
      } else {
        SyncReturnsHandler();
        data->promise->set_value(libfuzzer::RETURN_CONTINUE);
      }
    } else {
      data->promise->set_exception(
          std::make_exception_ptr(std::runtime_error("Environment is shut down")));
    }
  } catch (const Napi::Error &error) {
    // JS exception thrown by invocation of the fuzz target.
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
Napi::Value StartFuzzingAsync(const Napi::CallbackInfo &info) {
  if (info.Length() != 2 || !info[0].IsFunction() || !info[1].IsArray()) {
    throw Napi::Error::New(info.Env(),
                           "Need two arguments, which must be the fuzz target "
                           "function and an array of libfuzzer arguments");
  }

  auto fuzz_target = info[0].As<Napi::Function>();
  auto fuzzer_args = LibFuzzerArgs(info.Env(), info[1].As<Napi::Array>());

  // Store the JS fuzz target and corresponding environment, so that the C++
  // fuzz target can use them to call back into JS.
  auto *context = new AsyncFuzzTargetContext(info.Env());

  gTSFN = TSFN::New(
      info.Env(),         // Env
      fuzz_target,        // Callback
      "FuzzerAsyncAddon", // Name
      0,                  // Unlimited Queue
      1,                  // Only one thread will use this initially
      context,            // Context object passed into the callback
      [](Napi::Env env, FinalizerDataType *, AsyncFuzzTargetContext *ctx) {
        // This finalizer is executed in the main event loop context
        ctx->native_thread.join();
        if (!ctx->is_resolved) {
          ctx->deferred.Resolve(env.Undefined());
        }
        delete ctx;
      });

  // Start libFuzzer in a separate thread to not block the JavaScript event
  // loop.
  context->native_thread = std::thread(
      [](const std::vector<std::string> &fuzzer_args) {
        signal(SIGSEGV, ErrorSignalHandler);
        StartLibFuzzer(fuzzer_args, FuzzCallbackAsync);
        gTSFN.Release();
      },
      std::move(fuzzer_args));

  // Return promise to calling JS code to await fuzzing completion.
  return context->deferred.Promise();
}
