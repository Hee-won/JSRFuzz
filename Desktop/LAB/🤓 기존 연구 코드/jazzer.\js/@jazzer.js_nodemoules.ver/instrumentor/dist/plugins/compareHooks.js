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
exports.compareHooks = void 0;
const core_1 = require("@babel/core");
const types_1 = require("@babel/types");
const helpers_1 = require("./helpers");
function compareHooks() {
    return {
        visitor: {
            BinaryExpression(path) {
                // TODO: Investigate this type, it can not be passed to the call expression
                if ((0, types_1.isPrivateName)(path.node.left)) {
                    return;
                }
                let hookFunctionName;
                if (isStringCompare(path.node)) {
                    hookFunctionName = "Fuzzer.tracer.traceStrCmp";
                }
                else if (isNumberCompare(path.node)) {
                    hookFunctionName = "Fuzzer.tracer.traceNumberCmp";
                }
                else {
                    return;
                }
                path.replaceWith(core_1.types.callExpression(core_1.types.identifier(hookFunctionName), [
                    path.node.left,
                    path.node.right,
                    core_1.types.stringLiteral(path.node.operator),
                    (0, helpers_1.fakePC)(),
                ]));
            },
            SwitchStatement(path) {
                if (!(0, types_1.isIdentifier)(path.node.discriminant)) {
                    return;
                }
                const id = path.node.discriminant;
                for (const i in path.node.cases) {
                    const test = path.node.cases[i].test;
                    if (test) {
                        path.node.cases[i].test = core_1.types.callExpression(core_1.types.identifier("Fuzzer.tracer.traceAndReturn"), [id, test, (0, helpers_1.fakePC)()]);
                    }
                }
            },
        },
    };
}
exports.compareHooks = compareHooks;
function isStringCompare(exp) {
    // One operand has to be a string literal but not both
    if ((!(0, types_1.isStringLiteral)(exp.left) && !(0, types_1.isStringLiteral)(exp.right)) ||
        ((0, types_1.isStringLiteral)(exp.left) && (0, types_1.isStringLiteral)(exp.right))) {
        return false;
    }
    // Only support equals and not equals operators, the other ones can
    // not be forwarded to libFuzzer
    return ["==", "===", "!=", "!=="].includes(exp.operator);
}
function isNumberCompare(exp) {
    // One operand has to be a string literal but not both
    if ((!(0, types_1.isNumericLiteral)(exp.left) && !(0, types_1.isNumericLiteral)(exp.right)) ||
        ((0, types_1.isNumericLiteral)(exp.left) && (0, types_1.isNumericLiteral)(exp.right))) {
        return false;
    }
    return ["==", "===", "!=", "!==", ">", ">=", "<", "<="].includes(exp.operator);
}
//# sourceMappingURL=compareHooks.js.map