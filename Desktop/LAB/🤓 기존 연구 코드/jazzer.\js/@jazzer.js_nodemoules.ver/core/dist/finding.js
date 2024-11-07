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
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.errorName = exports.cleanErrorStack = exports.printFinding = exports.reportAndThrowFinding = exports.reportFinding = exports.clearFirstFinding = exports.FuzzerSignalFinding = exports.Finding = void 0;
const os_1 = require("os");
const path_1 = require("path");
const process_1 = __importDefault(require("process"));
const api_1 = require("./api");
const firstFinding = "firstFinding";
class Finding extends Error {
}
exports.Finding = Finding;
class FuzzerSignalFinding extends Finding {
    exitCode;
    constructor(signal) {
        super(signal == 11
            ? "Segmentation Fault"
            : `Fuzzing stopped by signal ${signal}`);
        // Signals should exit with code 128+n, see
        // https://tldp.org/LDP/abs/html/exitcodes.html
        this.exitCode = signal === 0 ? 0 : 128 + signal;
    }
}
exports.FuzzerSignalFinding = FuzzerSignalFinding;
// The first finding reported by any bug detector will be saved in the global jazzerJs object.
// This variable has to be cleared every time when the fuzzer is finished
// processing an input (only relevant for modes where the fuzzing continues
// after finding an error, e.g. fork mode, Jest regression mode, fuzzing that
// ignores errors mode, etc.).
function getFirstFinding() {
    return (0, api_1.getJazzerJsGlobal)(firstFinding);
}
function clearFirstFinding() {
    const lastFinding = getFirstFinding();
    (0, api_1.setJazzerJsGlobal)(firstFinding, undefined);
    return lastFinding;
}
exports.clearFirstFinding = clearFirstFinding;
/**
 * Save the first finding reported by any bug detector.
 *
 * @param cause - The finding to be reported.
 * @param containStack - Whether the finding should contain a stack trace or not.
 */
function reportFinding(cause, containStack = true) {
    // After saving the first finding, ignore all subsequent errors.
    if (getFirstFinding()) {
        return;
    }
    if (typeof cause === "string") {
        cause = new Finding(cause);
    }
    if (!containStack) {
        cause.stack = cause.message;
    }
    (0, api_1.setJazzerJsGlobal)(firstFinding, cause);
    return cause;
}
exports.reportFinding = reportFinding;
/**
 * Save the first finding reported by any bug detector and throw it to
 * potentially abort the current execution.
 *
 * @param cause - The finding to be saved and thrown.
 * @param containStack - Whether the finding should contain a stack trace or not.
 */
function reportAndThrowFinding(cause, containStack = true) {
    throw reportFinding(cause, containStack);
}
exports.reportAndThrowFinding = reportAndThrowFinding;
/**
 * Prints a finding, or more generally some kind of error, to stderr.
 */
function printFinding(error, print = process_1.default.stderr.write.bind(process_1.default.stderr)) {
    print(`==${process_1.default.pid}== `);
    if (!(error instanceof Finding)) {
        print("Uncaught Exception: ");
    }
    // Error could be emitted from within another environment (e.g. vm, window, frame),
    // hence, don't rely on instanceof checks.
    if (isError(error)) {
        if (error.stack) {
            cleanErrorStack(error);
            print(error.stack);
        }
        else {
            print(error.message);
        }
    }
    else if (typeof error === "string" || error instanceof String) {
        print(error.toString());
    }
    else {
        print("unknown");
    }
    print(os_1.EOL);
}
exports.printFinding = printFinding;
function isError(arg) {
    return (arg !== undefined && arg !== null && arg.message !== undefined);
}
function hasStack(arg) {
    return (arg !== undefined && arg !== null && arg.stack !== undefined);
}
function cleanErrorStack(error) {
    if (!hasStack(error) || !error.stack)
        return;
    if (error instanceof Finding) {
        // Remove the "Error :" prefix of the finding message from the stack trace.
        error.stack = error.stack.replace(`Error: ${error.message}\n`, `${error.message}\n`);
    }
    // Ignore all lines related to Jazzer.js internals. This includes stack frames on top,
    // like bug detector and reporting ones, and stack frames on the bottom, like the function
    // wrapper.
    const filterCriteria = [
        `@jazzer.js${path_1.sep}`,
        `jazzer.js${path_1.sep}packages${path_1.sep}`,
        `jazzer.js${path_1.sep}core${path_1.sep}`,
        `..${path_1.sep}..${path_1.sep}packages${path_1.sep}`, // local/filesystem dependencies
    ];
    error.stack = error.stack
        .split("\n")
        .filter((line) => !filterCriteria.some((criterion) => line.includes(criterion)))
        .join("\n");
}
exports.cleanErrorStack = cleanErrorStack;
function errorName(error) {
    if (error instanceof Error) {
        // error objects
        return error.name;
    }
    else if (typeof error !== "object") {
        // primitive types
        return String(error);
    }
    else {
        // Arrays and objects can not be converted to a proper name and so
        // not be stated as expected error.
        return "unknown";
    }
}
exports.errorName = errorName;
//# sourceMappingURL=finding.js.map