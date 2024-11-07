# @jazzer.js/core

This is the main entry point and all most users have to install as a
dev-dependency, so that they can fuzz their projects.

The `@jazzer.js/core` module provide a CLI interface via the `jazzer` command.
It can be used by `npx` or node script command. To display a command
documentation use the `--help` flag.

```shell
npx jazzer --help
```

The `core` module also provides the function `startFuzzing(options: Options)`as
entry point for further integrations and external tools.

## Install

Using npm:

```sh
npm install --save-dev @jazzer.js/core
```

## Documentation

See
[Jazzer.js README](https://github.com/CodeIntelligenceTesting/jazzer.js#readme)
for more information or the
[issues](https://github.com/CodeIntelligenceTesting/jazzer.js/issues?q=is%3Aissue+is%3Aopen)
associated with it.


## Options


### **Positionals:**

- **fuzz_target**:  
  Name of the module that exports the fuzz target function.  
  *Type*: `string`

- **corpus**:  
  Paths to the corpus directories. If not provided, no initial seeds are used, nor are interesting inputs saved.
  경로를 지정하지 않으면 초기 시드가 사용되지 않으며, 흥미로운 입력도 저장되지 않습니다.  
  *Type*: `string` (파일의 path가 string으로 주어져야한다는 뜻)

---

### **Fuzzer Options:**

- **`-f, --fuzz_entry_point, --fuzz_function`**:  
  Name of the fuzz test entry point. It must be an exported function with a single `Buffer` parameter. 
  퍼즈 테스트의 진입점이 되는 함수의 이름을 지정합니다. 이 함수는 반드시 단일 Buffer 매개변수를 가져야 합니다. (기본값: "fuzz")
  *Type*: `string`  
  *Default*: `"fuzz"`

- **`-i, --includes, --instrumentation_includes`**:  
  Part of the file path names to include in the instrumentation. A trailing `/` should be used for directories.  
  계측 대상에 포함할 파일 경로의 일부를 지정합니다. 디렉터리일 경우 경로 뒤에 /를 추가해야 합니다.
  `"*"` can be used to include all files. Can be specified multiple times.  
  "*"는 모든 파일을 포함하는 데 사용할 수 있습니다. 여러 번 지정할 수 있습니다.
  *Type*: `array`  
  *Default*: `["*"]`

- **`-e, --excludes, --instrumentation_excludes`**:  
  Part of the file path names to exclude from instrumentation. A trailing `/` should be used for directories.  
  계측에서 제외할 파일 경로의 일부를 지정합니다. 디렉터리일 경우 경로 뒤에 /를 추가해야 합니다.
  `"*"` can be used to exclude all files. Can be specified multiple times.
  "*"는 모든 파일을 제외하는 데 사용할 수 있습니다. 여러 번 지정할 수 있습니다.  
  *Type*: `array`  
  *Default*: `["node_modules"]`

- **`-h, --custom_hooks`**:  
  Allow users to hook functions. Useful for writing bug detectors, stubbing, and feedback functions.  
  사용자가 함수를 훅으로 사용할 수 있도록 허용합니다. 이는 버그 탐지기를 작성하거나, 대체 함수(stubbing)를 작성하거나, 퍼저를 위한 피드백 함수를 작성할 때 사용할 수 있습니다.
  *Type*: `array`  
  *Default*: `[]`

- **`--disable_bug_detectors`**:  
  Disable internal bug detectors. By default, all bug detectors are enabled. 
  내부 버그 탐지기를 비활성화합니다. 기본적으로 모든 버그 탐지기는 활성화되어 있습니다.
  Use the `.*` pattern to disable all. Available bug detectors include:
  .* 패턴을 사용하면 모든 버그 탐지기를 비활성화할 수 있습니다. 사용할 수 있는 버그 탐지기는 다음과 같습니다:
  - `command-injection`
  - `path-traversal`
  - `prototype-pollution`  
  *Type*: `array`  
  *Default*: `[]`

- **`-m, --mode`**:  
  Specifies whether to run in fuzzing mode (`fuzzing`) or regression mode (`regression`). Regression mode is useful for using corpus entries and generating coverage reports. 
  퍼징 모드(fuzzing)로 실행할지, 아니면 기존 코퍼스 항목을 사용해 대상 함수만 호출할지(regression) 모드를 설정합니다. 회귀 모드는 커버리지 보고서만 생성할 때 유용합니다. 
  *Type*: `string`  
  *Default*: `"fuzzing"`

- **`-d, --dry_run`**:  
  Perform a run with fuzzing instrumentation disabled. 
  instrumentation이 비활성화된 상태에서 실행을 수행합니다. 
  *Type*: `boolean`  
  *Default*: `false`

- **`--timeout`**:  
  Timeout in milliseconds for each fuzz test execution.
  각 퍼즈 테스트 실행에 대한 제한 시간을 밀리초 단위로 지정합니다.  
  *Type*: `number`  
  *Default*: `5000`

- **`--sync`**:  
  Run the fuzz target synchronously.  
  *Type*: `boolean`  
  *Default*: `false`

- **`-v, --verbose`**:  
  Enable verbose debugging logs.  
  *Type*: `boolean`  
  *Default*: `false`

---

### **Coverage Options:**

- **`--coverage, --cov`**:  
  Enable code coverage.  
  *Type*: `boolean`  
  *Default*: `false`

- **`--coverage_directory, --cov_dir`**:  
  Directory for storing coverage reports.  
  *Type*: `string`  
  *Default*: `"coverage"`

- **`--coverage_reporters, --cov_reporters`**:  
  A list of reporter names for writing coverage reports.  
  *Type*: `array`  
  *Default*: `["json", "text", "lcov", "clover"]`

---

### **General Options:**

- **`--version`**:  
  Show version number.  
  *Type*: `boolean`

- **`--help`**:  
  Show help.  
  *Type*: `boolean`

---