#!/usr/bin/env node
"use strict";
/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || function (mod) {
    if (mod && mod.__esModule) return mod;
    var result = {};
    if (mod != null) for (var k in mod) if (k !== "default" && Object.prototype.hasOwnProperty.call(mod, k)) __createBinding(result, mod, k);
    __setModuleDefault(result, mod);
    return result;
};
Object.defineProperty(exports, "__esModule", { value: true });
const yargs_1 = __importStar(require("yargs"));
const core_1 = require("./core");
const options_1 = require("./options");
const utils_1 = require("./utils");
// Use yargs to parse command line arguments and provide a nice CLI experience.
// Default values are provided by the options module and must not be set by yargs.
// To still display the default values in the help message, they are only set as
// descriptions.
// Handling of unsupported parameters is also done via the options module.
(0, yargs_1.default)(process.argv.slice(2))
    .scriptName("jazzer")
    .parserConfiguration({
    "camel-case-expansion": false,
    "strip-aliased": true,
    "strip-dashed": true,
    "greedy-arrays": false,
})
    .example("$0 package/target -i packages/foo -i packages/bar", 'Start a fuzzing run using the "fuzz" function exported by "target" ' +
    'and only instrument code in the "packages/a" and "packages/b" modules.')
    .example("$0 package/target corpus -- -max_total_time=60", 'Start a fuzzing run using the "fuzz" function exported by "target" ' +
    'and use the directory "corpus" to store newly generated inputs. ' +
    'Also pass the "-max_total_time" flag to the internal fuzzing engine ' +
    "(libFuzzer) to stop the fuzzing run after 60 seconds.")
    .epilogue("Happy fuzzing!")
    .command("$0 <fuzz_target> [corpus..]", "Coverage-guided, in-process fuzzer for the Node.js platform. \n\n" +
    'The "target" module has to export a function "fuzz" which accepts ' +
    "a byte array as first parameter and uses that to invoke the actual " +
    "function to fuzz.\n\n" +
    'The "corpus" directory is optional and can be used to provide initial ' +
    "seed input. It is also used to store interesting inputs between fuzzing " +
    "runs.\n\n" +
    "To pass options to the internal fuzzing engine (libFuzzer) use a " +
    'double-dash, "--", to mark the end of the normal fuzzer arguments. ' +
    "An example is shown in the examples section of this help message.", (yargs) => {
    yargs
        .positional("fuzz_target", {
        demandOption: true,
        describe: "Name of the module that exports the fuzz target function.",
        type: "string",
    })
        .positional("corpus", {
        array: true,
        describe: "Paths to the corpus directories. If not given, no initial " +
            "seeds are used nor interesting inputs saved.",
        type: "string",
    })
        .option("fuzz_entry_point", {
        alias: ["f", "fuzz_function"],
        defaultDescription: options_1.defaultOptions.fuzzEntryPoint,
        describe: "Name of the fuzz test entry point. It must be an exported " +
            "function with a single Buffer parameter",
        group: "Fuzzer:",
        type: "string",
    })
        .option("includes", {
        alias: ["i", "instrumentation_includes"],
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.includes)}`,
        describe: "Part of filepath names to include in the instrumentation. " +
            'A tailing "/" should be used to include directories and prevent ' +
            'confusion with filenames. "*" can be used to include all files.\n' +
            "Can be specified multiple times.",
        group: "Fuzzer:",
        type: "string",
    })
        .option("excludes", {
        alias: ["e", "instrumentation_excludes"],
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.excludes)}`,
        describe: "Part of filepath names to exclude in the instrumentation. " +
            'A tailing "/" should be used to exclude directories and prevent ' +
            'confusion with filenames. "*" can be used to exclude all files.\n' +
            "Can be specified multiple times.",
        group: "Fuzzer:",
        type: "string",
    })
        .option("id_sync_file", {
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.idSyncFile)}`,
        describe: "File used for sync edge ID generation. " +
            "Needed when fuzzing in multi-process modes",
        group: "Fuzzer:",
        hidden: true,
        type: "string",
    })
        .option("custom_hooks", {
        alias: "h",
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.customHooks)}`,
        describe: "Allow users to hook functions. This can be used for writing " +
            "bug detectors, for stubbing, and for writing feedback functions " +
            "for the fuzzer.",
        group: "Fuzzer:",
        type: "string",
    })
        .option("expected_errors", {
        alias: "x",
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.expectedErrors)}`,
        describe: "Expected errors can be specified as the class name of the " +
            "thrown error object or value of a thrown string. If expected " +
            "errors are defined, but none, or none of the expected ones are " +
            "raised during execution, the test execution fails." +
            'Examples: -x Error -x "My thrown error string"',
        group: "Fuzzer:",
        hidden: true,
        type: "string",
    })
        .option("disable_bug_detectors", {
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.disableBugDetectors)}`,
        describe: "A list of patterns to disable internal bug detectors. By default all internal " +
            "bug detectors are enabled. To disable all, use the '.*' pattern." +
            "Following bug detectors are available: " +
            "    command-injection\n" +
            "    path-traversal\n" +
            "    prototype-pollution\n",
        group: "Fuzzer:",
        type: "string",
    })
        .option("mode", {
        alias: "m",
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.mode)}`,
        describe: "Configure if fuzzing should be performed, 'fuzzing' mode, " +
            "or if the fuzz target should only be invoked using existing corpus " +
            "entries, 'regression' mode." +
            "Regression mode is helpful if only coverage reports should be generated.",
        group: "Fuzzer:",
        type: "string",
    })
        .option("dry_run", {
        alias: "d",
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.dryRun)}`,
        describe: "Perform a run with the fuzzing instrumentation disabled.",
        group: "Fuzzer:",
        type: "boolean",
    })
        .option("timeout", {
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.timeout)}`,
        describe: "Timeout in milliseconds for each fuzz test execution.",
        group: "Fuzzer:",
        type: "number",
    })
        .option("sync", {
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.sync)}`,
        describe: "Run the fuzz target synchronously.",
        group: "Fuzzer:",
        type: "boolean",
    })
        .option("verbose", {
        alias: "v",
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.verbose)}`,
        describe: "Enable verbose debugging logs.",
        group: "Fuzzer:",
        type: "boolean",
    })
        .option("coverage", {
        alias: "cov",
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.coverage)}`,
        describe: "Enable code coverage.",
        group: "Coverage:",
        type: "boolean",
    })
        .option("coverage_directory", {
        alias: "cov_dir",
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.coverageDirectory)}`,
        describe: "Directory for storing coverage reports.",
        group: "Coverage:",
        type: "string",
    })
        .option("coverage_reporters", {
        alias: "cov_reporters",
        array: true,
        defaultDescription: `${JSON.stringify(options_1.defaultOptions.coverageReporters)}`,
        describe: "A list of reporter names for writing coverage reports.",
        group: "Coverage:",
        type: "string",
    });
}, 
// eslint-disable-next-line @typescript-eslint/no-explicit-any
async (args) => {
    (0, options_1.setParameterResolverValue)(options_1.ParameterResolverIndex.CommandLineArguments, (0, utils_1.prepareArgs)(args));
    return (0, core_1.startFuzzing)((0, options_1.buildOptions)()).then(({ returnCode, error }) => {
        if (returnCode !== core_1.FuzzingExitCode.Ok) {
            (0, yargs_1.exit)(returnCode, error instanceof Error ? error : new Error("Unknown error"));
        }
    });
})
    .help().argv;
//# sourceMappingURL=cli.js.map