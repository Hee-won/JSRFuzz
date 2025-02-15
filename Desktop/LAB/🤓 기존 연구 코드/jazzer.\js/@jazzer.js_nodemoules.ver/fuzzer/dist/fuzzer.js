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
Object.defineProperty(exports, "__esModule", { value: true });
exports.fuzzer = void 0;
const addon_1 = require("./addon");
const coverage_1 = require("./coverage");
const trace_1 = require("./trace");
exports.fuzzer = {
    coverageTracker: coverage_1.coverageTracker,
    tracer: trace_1.tracer,
    startFuzzing: addon_1.addon.startFuzzing,
    startFuzzingAsync: addon_1.addon.startFuzzingAsync,
    printAndDumpCrashingInput: addon_1.addon.printAndDumpCrashingInput,
    printReturnInfo: addon_1.addon.printReturnInfo,
};
//# sourceMappingURL=fuzzer.js.map