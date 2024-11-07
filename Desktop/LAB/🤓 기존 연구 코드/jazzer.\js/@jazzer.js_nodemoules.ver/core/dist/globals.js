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
exports.getOrSetJazzerJsGlobal = exports.getJazzerJsGlobal = exports.setJazzerJsGlobal = exports.jazzerJs = void 0;
// Require the external initialization to set this map in the globalThis object
// before it is used here.
exports.jazzerJs = new Map();
function setJazzerJsGlobal(name, value) {
    if (!globalThis.JazzerJS) {
        throw new Error("JazzerJS global not initialized");
    }
    globalThis.JazzerJS.set(name, value);
}
exports.setJazzerJsGlobal = setJazzerJsGlobal;
function getJazzerJsGlobal(name) {
    return globalThis.JazzerJS?.get(name);
}
exports.getJazzerJsGlobal = getJazzerJsGlobal;
function getOrSetJazzerJsGlobal(name, defaultValue) {
    const value = getJazzerJsGlobal(name);
    if (value === undefined) {
        setJazzerJsGlobal(name, defaultValue);
        return defaultValue;
    }
    return value;
}
exports.getOrSetJazzerJsGlobal = getOrSetJazzerJsGlobal;
//# sourceMappingURL=globals.js.map