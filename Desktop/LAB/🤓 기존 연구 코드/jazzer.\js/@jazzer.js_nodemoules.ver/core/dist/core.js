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
var __exportStar = (this && this.__exportStar) || function(m, exports) {
    for (var p in m) if (p !== "default" && !Object.prototype.hasOwnProperty.call(exports, p)) __createBinding(exports, m, p);
};
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.setParameterResolverValue = exports.ParameterResolverIndex = exports.defaultOptions = exports.buildOptions = exports.FuzzedDataProvider = exports.asFindingAwareFuzzFn = exports.startFuzzingNoInit = exports.startFuzzing = exports.registerGlobals = exports.initFuzzing = exports.FuzzingResult = exports.FuzzingExitCode = void 0;
const fs = __importStar(require("fs"));
const path_1 = __importDefault(require("path"));
const libCoverage = __importStar(require("istanbul-lib-coverage"));
const libReport = __importStar(require("istanbul-lib-report"));
const reports = __importStar(require("istanbul-reports"));
const tmp = __importStar(require("tmp"));
const fuzzer = __importStar(require("@jazzer.js/fuzzer"));
const hooking = __importStar(require("@jazzer.js/hooking"));
const instrumentor_1 = require("@jazzer.js/instrumentor");
const callback_1 = require("./callback");
const finding_1 = require("./finding");
const globals_1 = require("./globals");
const options_1 = require("./options");
const utils_1 = require("./utils");
// Remove temporary files on exit
tmp.setGracefulCleanup();
// Possible fuzzing exit codes. libFuzzer uses exit code 77 in case of a crash,
// use the same one for uncaught exceptions and bug detector findings.
var FuzzingExitCode;
(function (FuzzingExitCode) {
    // Fuzzer exited normally without finding.
    FuzzingExitCode[FuzzingExitCode["Ok"] = 0] = "Ok";
    // libFuzzers crash exit code.
    FuzzingExitCode[FuzzingExitCode["Finding"] = 77] = "Finding";
    // Unexpected or missing finding.
    FuzzingExitCode[FuzzingExitCode["UnexpectedError"] = 78] = "UnexpectedError";
})(FuzzingExitCode || (exports.FuzzingExitCode = FuzzingExitCode = {}));
class FuzzingResult {
    returnCode;
    error;
    constructor(returnCode, error) {
        this.returnCode = returnCode;
        this.error = error;
    }
}
exports.FuzzingResult = FuzzingResult;
async function initFuzzing(options) {
    const instrumentor = new instrumentor_1.Instrumentor(options.includes, options.excludes, options.customHooks, options.coverage, options.dryRun, options.idSyncFile
        ? new instrumentor_1.FileSyncIdStrategy(options.idSyncFile)
        : new instrumentor_1.MemorySyncIdStrategy());
    (0, instrumentor_1.registerInstrumentor)(instrumentor);
    // Dynamic import works only with javascript files, so we have to manually specify the directory with the
    // transpiled bug detector files. 동적 import는 JavaScript 파일에만 적용
    const possibleBugDetectorFiles = getFilteredBugDetectorPaths(path_1.default.join(__dirname, "../../bug-detectors/dist/internal"), options.disableBugDetectors);
    if (process.env.JAZZER_DEBUG) {
        console.error("INFO: [BugDetector] Loading bug detectors: \n   " +
            possibleBugDetectorFiles.join("\n   "));
    }
    // Load bug detectors before loading custom hooks because some bug detectors can be configured in the
    // custom hooks file.
    await Promise.all(possibleBugDetectorFiles.map(utils_1.ensureFilepath).map(utils_1.importModule));
    await Promise.all(options.customHooks.map(utils_1.ensureFilepath).map(utils_1.importModule));
    await hooking.hookManager.finalizeHooks();
    return instrumentor;
}
exports.initFuzzing = initFuzzing;
function registerGlobals(options, 
// eslint-disable-next-line @typescript-eslint/no-explicit-any
globals = [globalThis]) {
    globals.forEach((global) => {
        global.Fuzzer = fuzzer.fuzzer;
        global.HookManager = hooking.hookManager;
        global.options = options;
        global.JazzerJS = globals_1.jazzerJs;
    });
}
exports.registerGlobals = registerGlobals;
// Filters out disabled bug detectors and prepares all the others for dynamic import.
// This functionality belongs to the bug-detector module but no dependency from
// core to bug-detectors is allowed.
function getFilteredBugDetectorPaths(bugDetectorsDirectory, disableBugDetectors) {
    const disablePatterns = disableBugDetectors.map((pattern) => new RegExp(pattern));
    return (fs
        .readdirSync(bugDetectorsDirectory)
        // The compiled "internal" directory contains several files such as .js.map and .d.ts.
        // We only need the .js files.
        // Here we also filter out bug detectors that should be disabled.
        .filter((bugDetectorPath) => {
        if (!bugDetectorPath.endsWith(".js")) {
            return false;
        }
        // Dynamic imports need .js files.
        const bugDetectorName = path_1.default.basename(bugDetectorPath, ".js");
        // Checks in the global options if the bug detector should be loaded.
        const shouldDisable = disablePatterns.some((pattern) => pattern.test(bugDetectorName));
        if (shouldDisable) {
            console.error(`Skip loading bug detector "${bugDetectorName}" because of user-provided pattern.`);
        }
        return !shouldDisable;
    })
        // Get absolute paths for each bug detector.
        .map((file) => path_1.default.join(bugDetectorsDirectory, file)));
}
async function startFuzzing(options) {
    registerGlobals(options);
    await initFuzzing(options);
    const fuzzFn = await loadFuzzFunction(options);
    const findingAwareFuzzFn = asFindingAwareFuzzFn(fuzzFn);
    return startFuzzingNoInit(findingAwareFuzzFn, options).finally(() => {
        // These post fuzzing actions are only required for invocations through the CLI,
        // other means of invocation, e.g. via Jest, don't need them.
        fuzzer.fuzzer.printReturnInfo(options.sync);
        processCoverage(options.coverageDirectory, options.coverageReporters);
    });
}
exports.startFuzzing = startFuzzing;
async function startFuzzingNoInit(fuzzFn, options) {
    // Signal handler that stops fuzzing when the process receives a signal.
    // The signal is raised as a finding and orderly shuts down the fuzzer, as that's
    // necessary to generate coverage reports and print debug information.
    // Currently only SIGINT is handled this way, as SIGSEGV has to be handled
    // by the native addon and directly stops the process.
    const signalHandler = (signal) => {
        (0, finding_1.reportFinding)(new finding_1.FuzzerSignalFinding(signal), false);
    };
    process.on("SIGINT", () => signalHandler(0));
    try {
        const fuzzerOptions = (0, options_1.buildFuzzerOption)(options);
        if (options.sync) {
            await fuzzer.fuzzer.startFuzzing(fuzzFn, fuzzerOptions, 
            // In synchronous mode, we cannot use the SIGINT handler in Node,
            // because the event loop is blocked by the fuzzer, and the handler
            // won't be called until the fuzzing process is finished.
            // Hence, we pass a callback function to the native fuzzer and
            // register a SIGINT handler there.
            signalHandler);
        }
        else {
            await fuzzer.fuzzer.startFuzzingAsync(fuzzFn, fuzzerOptions);
        }
        // Fuzzing ended without a finding, due to -max_total_time or -runs.
        return reportFuzzingResult(undefined, options.expectedErrors);
    }
    catch (e) {
        // Fuzzing produced an error, e.g. unhandled exception or bug detector finding.
        return reportFuzzingResult(e, options.expectedErrors);
    }
}
exports.startFuzzingNoInit = startFuzzingNoInit;
function reportFuzzingResult(error, expectedErrors) {
    if (process.env.JAZZER_DEBUG) {
        hooking.hookTracker.categorizeUnknown(HookManager.hooks).print();
    }
    // No error found, check if one is expected.
    if (!error) {
        if (expectedErrors.length) {
            const message = `ERROR: Received no error, but expected one of [${expectedErrors}].`;
            console.error(message);
            return new FuzzingResult(FuzzingExitCode.UnexpectedError, new Error(message));
        }
        // No error found and none expected, everything is fine.
        return new FuzzingResult(FuzzingExitCode.Ok);
    }
    // Error found and expected, check if it's one of the expected ones.
    if (expectedErrors.length) {
        const name = (0, finding_1.errorName)(error);
        if (expectedErrors.includes(name)) {
            console.error(`INFO: Received expected error "${name}".`);
            return new FuzzingResult(FuzzingExitCode.Ok, error);
        }
        else {
            console.error(`ERROR: Received error "${name}" is not in expected errors [${expectedErrors}].`);
            return new FuzzingResult(FuzzingExitCode.UnexpectedError, error);
        }
    }
    // Check if signal finding was reported, which might result in a normal termination.
    if (error instanceof finding_1.FuzzerSignalFinding &&
        error.exitCode === FuzzingExitCode.Ok) {
        return new FuzzingResult(FuzzingExitCode.Ok);
    }
    // Error found, but no specific one expected.
    return new FuzzingResult(FuzzingExitCode.Finding, error);
}
function processCoverage(coverageDirectory, coverageReporters) {
    // Generate a coverage report in fuzzing mode (non-jest). 
    // The coverage report for the jest-runner is generated by jest internally (as long as '--coverage' is set).
    if (global.__coverage__) {
        const coverageMap = libCoverage.createCoverageMap(global.__coverage__);
        const context = libReport.createContext({
            dir: coverageDirectory,
            watermarks: {},
            coverageMap: coverageMap,
        });
        coverageReporters.forEach((reporter) => reports.create(reporter).execute(context));
    }
}
async function loadFuzzFunction(options) {
    const fuzzTarget = await (0, utils_1.importModule)(options.fuzzTarget);
    if (!fuzzTarget) {
        throw new Error(`${options.fuzzTarget} could not be imported successfully"`);
    }
    const fuzzFn = fuzzTarget[options.fuzzEntryPoint];
    if (typeof fuzzFn !== "function") {
        throw new Error(`${options.fuzzTarget} does not export function "${options.fuzzEntryPoint}"`);
    }
    return fuzzFn;
}
/**
 * Wraps the given fuzz target function to handle errors from both the fuzz target and bug detectors.
 * Ensures that errors thrown by bug detectors have higher priority than errors in the fuzz target.
 */
function asFindingAwareFuzzFn(originalFuzzFn, dumpCrashingInput = true) {
    function printAndDump(error) {
        (0, finding_1.cleanErrorStack)(error);
        if (!(error instanceof finding_1.FuzzerSignalFinding &&
            error.exitCode === FuzzingExitCode.Ok)) {
            (0, finding_1.printFinding)(error);
            if (dumpCrashingInput) {
                fuzzer.fuzzer.printAndDumpCrashingInput();
            }
        }
    }
    function throwIfError(fuzzTargetError) {
        const error = (0, finding_1.clearFirstFinding)() ?? fuzzTargetError;
        if (error) {
            printAndDump(error);
            throw error;
        }
    }
    if (originalFuzzFn.length === 1) {
        return ((data) => {
            function isPromiseLike(arg) {
                return !!arg && arg.then !== undefined;
            }
            let fuzzTargetError;
            let result = undefined;
            const callbacks = (0, callback_1.getCallbacks)();
            try {
                callbacks.runBeforeEachCallbacks();
                result = originalFuzzFn(data);
                // Explicitly set promise handlers to process findings, but still return
                // the fuzz target result directly, so that sync execution is still
                // possible.
                if (isPromiseLike(result)) {
                    result = result.then((result) => {
                        callbacks.runAfterEachCallbacks();
                        return throwIfError() ?? result;
                    }, (reason) => {
                        callbacks.runAfterEachCallbacks();
                        return throwIfError(reason);
                    });
                }
                else {
                    callbacks.runAfterEachCallbacks();
                }
            }
            catch (e) {
                callbacks.runAfterEachCallbacks();
                fuzzTargetError = e;
            }
            return throwIfError(fuzzTargetError) ?? result;
        });
    }
    else {
        return ((data, done) => {
            const callbacks = (0, callback_1.getCallbacks)();
            try {
                callbacks.runBeforeEachCallbacks();
                // Return result of fuzz target to enable sanity checks in C++ part.
                const result = originalFuzzFn(data, (err) => {
                    const error = (0, finding_1.clearFirstFinding)() ?? err;
                    if (error) {
                        printAndDump(error);
                    }
                    callbacks.runAfterEachCallbacks();
                    done(error);
                });
                // Check if any finding was reported by the invocation before the
                // callback was executed. As the callback in used for control flow,
                // don't run afterEach here.
                return throwIfError() ?? result;
            }
            catch (e) {
                callbacks.runAfterEachCallbacks();
                throwIfError(e);
            }
        });
    }
}
exports.asFindingAwareFuzzFn = asFindingAwareFuzzFn;
// Export public API from within core module for easy access.
__exportStar(require("./api"), exports);
var FuzzedDataProvider_1 = require("./FuzzedDataProvider");
Object.defineProperty(exports, "FuzzedDataProvider", { enumerable: true, get: function () { return FuzzedDataProvider_1.FuzzedDataProvider; } });
var options_2 = require("./options");
Object.defineProperty(exports, "buildOptions", { enumerable: true, get: function () { return options_2.buildOptions; } });
Object.defineProperty(exports, "defaultOptions", { enumerable: true, get: function () { return options_2.defaultOptions; } });
Object.defineProperty(exports, "ParameterResolverIndex", { enumerable: true, get: function () { return options_2.ParameterResolverIndex; } });
Object.defineProperty(exports, "setParameterResolverValue", { enumerable: true, get: function () { return options_2.setParameterResolverValue; } });
//# sourceMappingURL=core.js.map