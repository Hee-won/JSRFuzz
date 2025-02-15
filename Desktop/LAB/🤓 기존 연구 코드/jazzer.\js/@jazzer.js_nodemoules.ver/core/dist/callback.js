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
exports.registerBeforeEachCallback = exports.registerAfterEachCallback = exports.getCallbacks = exports.Callbacks = void 0;
const api_1 = require("./api");
/**
 * Callbacks can be registered in fuzz targets or bug detectors to be executed
 * before or after each fuzz target invocation.
 */
class Callbacks {
    _afterEachCallbacks = [];
    _beforeEachCallbacks = [];
    registerAfterEachCallback(callback) {
        this._afterEachCallbacks.push(callback);
    }
    registerBeforeEachCallback(callback) {
        this._beforeEachCallbacks.push(callback);
    }
    runAfterEachCallbacks() {
        this._afterEachCallbacks.forEach((c) => c());
    }
    runBeforeEachCallbacks() {
        this._beforeEachCallbacks.forEach((c) => c());
    }
}
exports.Callbacks = Callbacks;
const defaultCallbacks = new Callbacks();
function getCallbacks() {
    return (0, api_1.getOrSetJazzerJsGlobal)("callbacks", defaultCallbacks);
}
exports.getCallbacks = getCallbacks;
function registerAfterEachCallback(callback) {
    getCallbacks().registerAfterEachCallback(callback);
}
exports.registerAfterEachCallback = registerAfterEachCallback;
function registerBeforeEachCallback(callback) {
    getCallbacks().registerBeforeEachCallback(callback);
}
exports.registerBeforeEachCallback = registerBeforeEachCallback;
//# sourceMappingURL=callback.js.map