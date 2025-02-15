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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.spawnsSubprocess = exports.buildFuzzerOption = exports.buildOptions = exports.setParameterResolverValue = exports.ParameterResolverIndex = exports.fromSnakeCaseWithPrefix = exports.fromSnakeCase = exports.fromCamelCase = exports.defaultOptions = void 0;
const fs_1 = __importDefault(require("fs"));
const tmp = __importStar(require("tmp"));
const dictionary_1 = require("./dictionary");
exports.defaultOptions = Object.freeze({
    fuzzTarget: "",
    fuzzEntryPoint: "fuzz",
    includes: ["*"],
    excludes: ["node_modules"],
    dryRun: false,
    sync: false,
    fuzzerOptions: [],
    customHooks: [],
    expectedErrors: [],
    timeout: 5000,
    idSyncFile: "",
    coverage: false,
    coverageDirectory: "coverage",
    coverageReporters: ["json", "text", "lcov", "clover"],
    disableBugDetectors: [],
    mode: "fuzzing",
    verbose: false,
});
const fromCamelCase = (key) => key;
exports.fromCamelCase = fromCamelCase;
const fromSnakeCase = (key) => {
    return key
        .toLowerCase()
        .replaceAll(/(_[a-z0-9])/g, (group) => group.toUpperCase().replace("_", ""));
};
exports.fromSnakeCase = fromSnakeCase;
const fromSnakeCaseWithPrefix = (prefix) => {
    const prefixKey = prefix.toLowerCase() + "_";
    return (key) => {
        return key.toLowerCase().startsWith(prefixKey)
            ? (0, exports.fromSnakeCase)(key.substring(prefixKey.length))
            : key;
    };
};
exports.fromSnakeCaseWithPrefix = fromSnakeCaseWithPrefix;
// Parameters can be passed in via environment variables, command line or
// configuration file, and subsequently overwrite the default ones and each other.
// The passed in values have to be set for externally provided parameters, e.g.
// CLI parameters, before resolving the final options object.
// Higher index means higher priority.
var ParameterResolverIndex;
(function (ParameterResolverIndex) {
    ParameterResolverIndex[ParameterResolverIndex["DefaultOptions"] = 1] = "DefaultOptions";
    ParameterResolverIndex[ParameterResolverIndex["ConfigurationFile"] = 2] = "ConfigurationFile";
    ParameterResolverIndex[ParameterResolverIndex["EnvironmentVariables"] = 3] = "EnvironmentVariables";
    ParameterResolverIndex[ParameterResolverIndex["CommandLineArguments"] = 4] = "CommandLineArguments";
})(ParameterResolverIndex || (exports.ParameterResolverIndex = ParameterResolverIndex = {}));
const defaultResolvers = {
    [ParameterResolverIndex.DefaultOptions]: {
        name: "Default options",
        transformKey: exports.fromCamelCase,
        failOnUnknown: true,
        parameters: exports.defaultOptions,
    },
    [ParameterResolverIndex.ConfigurationFile]: {
        name: "Configuration file",
        transformKey: exports.fromCamelCase,
        failOnUnknown: true,
        parameters: {},
    },
    [ParameterResolverIndex.EnvironmentVariables]: {
        name: "Environment variables",
        transformKey: (0, exports.fromSnakeCaseWithPrefix)("JAZZER"),
        failOnUnknown: false,
        parameters: process.env,
    },
    [ParameterResolverIndex.CommandLineArguments]: {
        name: "Command line arguments",
        transformKey: exports.fromSnakeCase,
        failOnUnknown: true,
        parameters: {},
    },
};
/**
 * Set the value object of a parameter resolver. Every resolver expects value
 * object parameter names in a specific format, e.g. camel case or snake case,
 * see the resolver definitions for details.
 */
function setParameterResolverValue(index, inputs) {
    // Includes and excludes must be set together.
    if (inputs && inputs.includes && !inputs.excludes) {
        inputs.excludes = [];
    }
    else if (inputs && inputs.excludes && !inputs.includes) {
        inputs.includes = [];
    }
    defaultResolvers[index].parameters = inputs;
}
exports.setParameterResolverValue = setParameterResolverValue;
/**
 * Build a complete `Option` object based on the parameter resolver chain.
 * Add externally passed in values via the `setParameterResolverValue` function,
 * before calling `buildOptions`.
 */
function buildOptions() {
    const options = Object.keys(defaultResolvers)
        .sort() // Don't presume an ordered object, this could be implementation specific.
        .reduce((accumulator, currentValue) => {
        const resolver = defaultResolvers[parseInt(currentValue)];
        return mergeOptions(resolver.parameters, accumulator, resolver.transformKey, resolver.failOnUnknown);
    }, defaultResolvers[ParameterResolverIndex.DefaultOptions].parameters);
    // Set verbose mode environment variable via option or node DEBUG environment variable.
    if (options.verbose || process.env.DEBUG) {
        process.env.JAZZER_DEBUG = "1";
    }
    return options;
}
exports.buildOptions = buildOptions;
function mergeOptions(input, defaults, transformKey, errorOnUnknown = true) {
    // Deep close the default options to avoid mutation.
    const options = JSON.parse(JSON.stringify(defaults));
    if (!input || typeof input !== "object") {
        return options;
    }
    Object.keys(input).forEach((key) => {
        const transformedKey = transformKey(key);
        if (!Object.hasOwn(options, transformedKey)) {
            if (errorOnUnknown) {
                throw new Error(`Unknown Jazzer.js option '${key}'`);
            }
            return;
        }
        // No way to dynamically resolve the types here, use (implicit) any for now.
        // @ts-ignore
        let resultValue = input[key];
        // Try to parse strings as JSON values to support setting arrays and
        // objects via environment variables.
        if (typeof resultValue === "string" || resultValue instanceof String) {
            try {
                resultValue = JSON.parse(resultValue.toString());
            }
            catch (ignore) {
                // Ignore parsing errors and continue with the string value.
            }
        }
        //@ts-ignore
        const keyType = typeof options[transformedKey];
        if (typeof resultValue !== keyType) {
            // @ts-ignore
            throw new Error(`Invalid type for Jazzer.js option '${key}', expected type '${keyType}'`);
        }
        // Deep clone value to avoid reference keeping and unintended mutations.
        // @ts-ignore
        options[transformedKey] = JSON.parse(JSON.stringify(resultValue));
    });
    return options;
}
function buildFuzzerOption(options) {
    if (process.env.JAZZER_DEBUG) {
        console.debug("DEBUG: [core] Jazzer.js initial fuzzer arguments: ");
        console.debug(options);
    }
    let params = [];
    params = optionDependentParams(options, params);
    params = forkedExecutionParams(params);
    params = (0, dictionary_1.useDictionaryByParams)(params);
    // libFuzzer has to ignore SIGINT and SIGTERM, as it interferes
    // with the Node.js signal handling.
    params = params.concat("-handle_int=0", "-handle_term=0", "-handle_segv=0", "-entropic=1", "-print_pcs=1", "-print_funcs=1", "-print_final_stats=1"); // 수정
    if (process.env.JAZZER_DEBUG) {
        console.debug("DEBUG: [core] Jazzer.js actually used fuzzer arguments: ");
        console.debug(params);
    }
    logInfoAboutFuzzerOptions(params);
    console.log(params); // 수정
    return params;
}
exports.buildFuzzerOption = buildFuzzerOption;
function logInfoAboutFuzzerOptions(fuzzerOptions) {
    fuzzerOptions.slice(1).forEach((element) => {
        if (element.length > 0 && element[0] != "-") {
            console.error("INFO: using inputs from:", element);
        }
    });
}
function optionDependentParams(options, params) {
    if (!options || !options.fuzzerOptions) {
        return params;
    }
    let opts = options.fuzzerOptions;
    if (options.mode === "regression") {
        // The last provided option takes precedence
        opts = opts.concat("-runs=0");
    }
    if (options.timeout <= 0) {
        throw new Error("timeout must be > 0");
    }
    const inSeconds = Math.ceil(options.timeout / 1000);
    opts = opts.concat(`-timeout=${inSeconds}`);
    return opts;
}
function forkedExecutionParams(params) {
    return [prepareLibFuzzerArg0(params), ...params];
}
function prepareLibFuzzerArg0(fuzzerOptions) {
    // When we run in a libFuzzer mode that spawns subprocesses, we create a wrapper script
    // that can be used as libFuzzer's argv[0]. In the fork mode, the main libFuzzer process
    // uses argv[0] to spawn further processes that perform the actual fuzzing.
    if (!spawnsSubprocess(fuzzerOptions)) {
        // Return a fake argv[0] to start the fuzzer if libFuzzer does not spawn new processes.
        return "unused_arg0_report_a_bug_if_you_see_this";
    }
    else {
        // Create a wrapper script and return its path.
        return createWrapperScript(fuzzerOptions);
    }
}
// These flags cause libFuzzer to spawn subprocesses.
const SUBPROCESS_FLAGS = ["fork", "jobs", "merge", "minimize_crash"];
function spawnsSubprocess(fuzzerOptions) {
    return fuzzerOptions.some((option) => SUBPROCESS_FLAGS.some((flag) => {
        const name = `-${flag}=`;
        return option.startsWith(name) && !option.startsWith("0", name.length);
    }));
}
exports.spawnsSubprocess = spawnsSubprocess;
function createWrapperScript(fuzzerOptions) {
    const jazzerArgs = process.argv.filter((arg) => arg !== "--" && fuzzerOptions.indexOf(arg) === -1);
    if (jazzerArgs.indexOf("--id_sync_file") === -1) {
        const idSyncFile = tmp.fileSync({
            mode: 0o600,
            prefix: "jazzer.js",
            postfix: "idSync",
        });
        jazzerArgs.push("--id_sync_file", idSyncFile.name);
        fs_1.default.closeSync(idSyncFile.fd);
    }
    const isWindows = process.platform === "win32";
    const scriptContent = `${isWindows ? "@echo off" : "#!/usr/bin/env sh"}
cd "${process.cwd()}"
${jazzerArgs.map((s) => '"' + s + '"').join(" ")} -- ${isWindows ? "%*" : "$@"}
`;
    const scriptTempFile = tmp.fileSync({
        mode: 0o700,
        prefix: "jazzer.js",
        postfix: "libfuzzer" + (isWindows ? ".bat" : ".sh"),
    });
    fs_1.default.writeFileSync(scriptTempFile.name, scriptContent);
    fs_1.default.closeSync(scriptTempFile.fd);
    return scriptTempFile.name;
}
//# sourceMappingURL=options.js.map