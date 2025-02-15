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
exports.jazzer = exports.exploreState = exports.guideTowardsContainment = exports.guideTowardsEquality = exports.getOrSetJazzerJsGlobal = exports.setJazzerJsGlobal = exports.getJazzerJsGlobal = exports.reportFinding = exports.reportAndThrowFinding = exports.addDictionary = exports.registerBeforeEachCallback = exports.registerAfterEachCallback = exports.instrumentationGuard = exports.registerInstrumentationPlugin = void 0;
const fuzzer_1 = require("@jazzer.js/fuzzer");
// Central place to export all public API functions to be used in fuzz targets,
// hooks and bug detectors. Don't use internal functions directly from those.
var instrumentor_1 = require("@jazzer.js/instrumentor");
Object.defineProperty(exports, "registerInstrumentationPlugin", { enumerable: true, get: function () { return instrumentor_1.registerInstrumentationPlugin; } });
Object.defineProperty(exports, "instrumentationGuard", { enumerable: true, get: function () { return instrumentor_1.instrumentationGuard; } });
var callback_1 = require("./callback");
Object.defineProperty(exports, "registerAfterEachCallback", { enumerable: true, get: function () { return callback_1.registerAfterEachCallback; } });
Object.defineProperty(exports, "registerBeforeEachCallback", { enumerable: true, get: function () { return callback_1.registerBeforeEachCallback; } });
var dictionary_1 = require("./dictionary");
Object.defineProperty(exports, "addDictionary", { enumerable: true, get: function () { return dictionary_1.addDictionary; } });
var finding_1 = require("./finding");
Object.defineProperty(exports, "reportAndThrowFinding", { enumerable: true, get: function () { return finding_1.reportAndThrowFinding; } });
Object.defineProperty(exports, "reportFinding", { enumerable: true, get: function () { return finding_1.reportFinding; } });
var globals_1 = require("./globals");
Object.defineProperty(exports, "getJazzerJsGlobal", { enumerable: true, get: function () { return globals_1.getJazzerJsGlobal; } });
Object.defineProperty(exports, "setJazzerJsGlobal", { enumerable: true, get: function () { return globals_1.setJazzerJsGlobal; } });
Object.defineProperty(exports, "getOrSetJazzerJsGlobal", { enumerable: true, get: function () { return globals_1.getOrSetJazzerJsGlobal; } });
exports.guideTowardsEquality = fuzzer_1.fuzzer.tracer.guideTowardsEquality;
exports.guideTowardsContainment = fuzzer_1.fuzzer.tracer.guideTowardsContainment;
exports.exploreState = fuzzer_1.fuzzer.tracer.exploreState;
// Export jazzer object for backwards compatibility.
exports.jazzer = {
    guideTowardsEquality: fuzzer_1.fuzzer.tracer.guideTowardsEquality,
    guideTowardsContainment: fuzzer_1.fuzzer.tracer.guideTowardsContainment,
    exploreState: fuzzer_1.fuzzer.tracer.exploreState,
};
//# sourceMappingURL=api.js.map