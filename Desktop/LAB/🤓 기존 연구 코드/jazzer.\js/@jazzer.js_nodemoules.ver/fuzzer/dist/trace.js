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
exports.exploreState = exports.tracer = void 0;
const addon_1 = require("./addon");
/**
 * Performs a string comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param s1 first compared string. s1 has the type `unknown` because we can only know the type at runtime.
 * @param s2 second compared string. s2 has the type `unknown` because we can only know the type at runtime.
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 * 두 문자열 s1, s2를 비교하고, 비교 결과에 따라 traceUnequalStrings를 호출할지 결정
 */
function traceStrCmp(s1, s2, operator, id) {
    let result = false;
    let shouldCallLibfuzzer = false;
    switch (operator) {
        case "==":
            result = s1 == s2;
            shouldCallLibfuzzer = !result;
            break;
        case "===":
            result = s1 === s2;
            shouldCallLibfuzzer = !result;
            break;
        case "!=":
            result = s1 != s2;
            shouldCallLibfuzzer = result;
            break;
        case "!==":
            result = s1 !== s2;
            shouldCallLibfuzzer = result;
            break;
    }
    if (shouldCallLibfuzzer &&
        s1 &&
        s2 &&
        typeof s1 === "string" &&
        typeof s2 === "string") {
        addon_1.addon.traceUnequalStrings(id, s1, s2);
    }
    return result;
}
/**
 * Performs an integer comparison between two strings and calls the corresponding native hook if needed.
 * This function replaces the original comparison expression and preserves the semantics by returning
 * the original result after calling the native hook.
 * @param n1 first compared number
 * @param n2 second compared number
 * @param operator the operator used in the comparison
 * @param id an unique identifier to distinguish between the different comparisons
 * @returns result of the comparison
 * 두 숫자 n1, n2를 비교하고, 비교 결과에 따라 traceIntegerCompare를 호출할지 결정
 */
function traceNumberCmp(n1, n2, operator, id) {
    if (Number.isInteger(n1) && Number.isInteger(n2)) {
        addon_1.addon.traceIntegerCompare(id, n1, n2);
    }
    switch (operator) {
        case "==":
            return n1 == n2;
        case "===":
            return n1 === n2;
        case "!=":
            return n1 != n2;
        case "!==":
            return n1 !== n2;
        case ">":
            return n1 > n2;
        case ">=":
            return n1 >= n2;
        case "<":
            return n1 < n2;
        case "<=":
            return n1 <= n2;
        default:
            throw `unexpected number comparison operator ${operator}`;
    }
}
function traceAndReturn(current, target, id) {
    switch (typeof target) {
        case "number":
            if (typeof current === "number") {
                if (Number.isInteger(current) && Number.isInteger(target)) {
                    addon_1.addon.traceIntegerCompare(id, current, target);
                }
            }
            break;
        case "string":
            if (typeof current === "string") {
                addon_1.addon.traceUnequalStrings(id, current, target);
            }
    }
    return target;
}
exports.tracer = {
    traceStrCmp,
    traceUnequalStrings: addon_1.addon.traceUnequalStrings,
    traceStringContainment: addon_1.addon.traceStringContainment,
    traceNumberCmp,
    traceAndReturn,
    tracePcIndir: addon_1.addon.tracePcIndir,
    guideTowardsEquality: guideTowardsEquality,
    guideTowardsContainment: guideTowardsContainment,
    exploreState: exploreState,
};
/**
 * Instructs the fuzzer to guide its mutations towards making `current` equal to `target`
 * current 문자열을 점진적으로 target에 가까워지도록 만듭니다.
 * If the relation between the raw fuzzer input and the value of `current` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * achieve equality.
 *
 * @param current a non-constant string observed during fuzz target execution
 * @param target a string that `current` should become equal to, but currently isn't
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
function guideTowardsEquality(current, target, id) {
    // Check types as JavaScript fuzz targets could provide wrong ones.
    // noinspection SuspiciousTypeOfGuard
    if (typeof current !== "string" ||
        typeof target !== "string" ||
        typeof id !== "number") {
        return;
    }
    exports.tracer.traceUnequalStrings(id, current, target);
}
/**
 * Instructs the fuzzer to guide its mutations towards making `haystack` contain `needle` as a substring.
 *
 * If the relation between the raw fuzzer input and the value of `haystack` is relatively
 * complex, running the fuzzer with the argument `-use_value_profile=1` may be necessary to
 * satisfy the substring check.
 * needle은 포함되어야 하는 문자열이고, haystack은 fuzzing 중 관찰된 문자열.
 * fuzzer는 haystack이 needle을 포함하도록 변이를 진행.
 * @param needle a string that should be contained in `haystack` as a substring, but
 *     currently isn't
 * @param haystack a non-constant string observed during fuzz target execution
 * @param id a (probabilistically) unique identifier for this particular compare hint
 */
function guideTowardsContainment(needle, haystack, id) {
    // Check types as JavaScript fuzz targets could provide wrong ones.
    // noinspection SuspiciousTypeOfGuard
    if (typeof needle !== "string" ||
        typeof haystack !== "string" ||
        typeof id !== "number") {
        return;
    }
    exports.tracer.traceStringContainment(id, needle, haystack);
}
/**
 * Instructs the fuzzer to attain as many possible values for the absolute value of `state`
 * as possible.
 *
 * Call this function from a fuzz target or a hook to help the fuzzer track partial progress
 * (e.g. by passing the length of a common prefix of two lists that should become equal) or
 * explore different values of state that is not directly related to code coverage.
 *
 * Note: This hint only takes effect if the fuzzer is run with the argument
 * `-use_value_profile=1`.
 *
 * @param state a numeric encoding of a state that should be varied by the fuzzer
 * @param id a (probabilistically) unique identifier for this particular state hint
 */
function exploreState(state, id) {
    // Check types as JavaScript fuzz targets could provide wrong ones.
    // noinspection SuspiciousTypeOfGuard
    if (typeof state !== "string" || typeof id !== "number") {
        return;
    }
    exports.tracer.tracePcIndir(id, state);
}
exports.exploreState = exploreState;
//# sourceMappingURL=trace.js.map