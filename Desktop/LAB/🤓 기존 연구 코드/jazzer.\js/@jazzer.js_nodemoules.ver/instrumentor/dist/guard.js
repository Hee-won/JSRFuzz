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
exports.instrumentationGuard = exports.InstrumentationGuard = void 0;
// instrumentation 안해도 되는 js 파일 선별
// Keep track of statements and expressions that should not be instrumented.
// This is necessary to avoid infinite recursion when instrumenting code.
class InstrumentationGuard {
    map = new Map();
    /**
     * Add a tag and a value to the guard. This can be used to look up if the value.
     * The value will be stringified internally before being added to the guard.
     * @example instrumentationGuard.add("AssignmentExpression", node.left);
     */
    add(tag, value) {
        if (!this.map.has(tag)) {
            this.map.set(tag, new Set());
        }
        this.map.get(tag)?.add(JSON.stringify(value));
    }
    /**
     * Check if a value with a given tag exists in the guard. The value will be stringified internally before being checked.
     * @example instrumentationGuard.has("AssignmentExpression", node.object);
     */
    has(expression, value) {
        return ((this.map.has(expression) &&
            this.map.get(expression)?.has(JSON.stringify(value))) ??
            false);
    }
}
exports.InstrumentationGuard = InstrumentationGuard;
exports.instrumentationGuard = new InstrumentationGuard();
//# sourceMappingURL=guard.js.map