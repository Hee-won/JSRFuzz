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
exports.functionHooks = void 0;
const core_1 = require("@babel/core");
const generator_1 = __importDefault(require("@babel/generator"));
const babel = __importStar(require("@babel/types"));
const hooking_1 = require("@jazzer.js/hooking");
function functionHooks(filepath) {
    return () => {
        return {
            visitor: {
                Function(path) {
                    if (path.node.params.every((param) => babel.isIdentifier(param))) {
                        const target = targetPath(path);
                        if (applyHooks(filepath, target, path.node)) {
                            path.skip();
                        }
                    }
                },
            },
        };
    };
}
exports.functionHooks = functionHooks;
function applyHooks(filepath, functionName, functionNode) {
    const matchedHooks = hooking_1.hookManager.matchingHooks(functionName, filepath);
    // We currently only handle hooking functions with identifiers as parameters.
    if (!functionNode.params.every((p) => babel.isIdentifier(p))) {
        return false;
    }
    if (!matchedHooks.hasHooks()) {
        hooking_1.hookTracker.addAvailable(filepath, functionName);
        return false;
    }
    for (const hook of matchedHooks.hooks) {
        hooking_1.hookTracker.addApplied(hook.pkg, hook.target);
    }
    // For arrow functions, the body can a single expression representing the value to be returned.
    // In this case, we replace the body by a block statement with a return statement.
    // This way, we can add calls to the hooks into the body.
    if (!babel.isBlockStatement(functionNode.body)) {
        functionNode.body = core_1.types.blockStatement([
            core_1.types.returnStatement(functionNode.body),
        ]);
    }
    // Bind the original function to <fn name>_original
    // replace all points by underscores in the function name
    const origFuncName = functionName.replace(/\./g, "_") + "_original";
    if (matchedHooks.hasReplaceHooks() || matchedHooks.hasAfterHooks()) {
        defineInternalFunctionWithOriginalImplementation(functionNode, origFuncName);
    }
    if (matchedHooks.hasReplaceHooks()) {
        addReplaceHooks(functionNode, matchedHooks, origFuncName);
    }
    if (matchedHooks.hasAfterHooks()) {
        addAfterHooks(functionNode, matchedHooks, origFuncName);
    }
    if (matchedHooks.hasBeforeHooks()) {
        addBeforeHooks(functionNode, matchedHooks);
    }
    (0, hooking_1.logHooks)(matchedHooks.hooks);
    return true;
}
function targetPath(path) {
    return path.getAncestry().reduce((acc, p) => {
        if ("id" in p.node && babel.isIdentifier(p.node.id)) {
            return addElementToPath(p.node.id.name, acc);
        }
        if ("key" in p.node) {
            if (babel.isIdentifier(p.node.key)) {
                return addElementToPath(p.node.key.name, acc);
            }
            else if (babel.isStringLiteral(p.node.key)) {
                return addElementToPath(p.node.key.value, acc);
            }
        }
        if (babel.isAssignmentExpression(p.node)) {
            return addElementToPath((0, generator_1.default)(p.node.left).code, acc);
        }
        return acc;
    }, "");
}
function addElementToPath(element, path) {
    const separator = path ? "." : "";
    return element + separator + path;
}
function defineInternalFunctionWithOriginalImplementation(functionNode, origFuncName) {
    functionNode.body = core_1.types.blockStatement([
        createInternalFunctionFromBody(origFuncName, 
        //TODO check this
        functionNode.params, functionNode.body),
    ]);
}
function addAfterHooks(functionNode, matchesResult, origFuncName) {
    const retVal = core_1.types.identifier(origFuncName + "_result");
    const origCal = callOriginalFunctionExpression(origFuncName, functionNode.params);
    if (matchesResult.afterHooks[0].async) {
        let thenChainCallExpr = origCal;
        for (const afterHook of matchesResult.afterHooks) {
            thenChainCallExpr = core_1.types.callExpression(core_1.types.memberExpression(thenChainCallExpr, core_1.types.identifier("then")), [
                asyncHookThenExpression(afterHook, functionNode.params, retVal),
            ]);
        }
        functionNode.body.body.push(core_1.types.returnStatement(thenChainCallExpr));
    }
    else {
        functionNode.body.body.push(core_1.types.variableDeclaration("const", [
            core_1.types.variableDeclarator(retVal, origCal),
        ]));
        for (const afterHook of matchesResult.afterHooks) {
            functionNode.body.body.push(core_1.types.expressionStatement(callHookExpression(afterHook, functionNode.params, [retVal])));
        }
        functionNode.body.body.push(core_1.types.returnStatement(retVal));
    }
}
function addReplaceHooks(functionNode, matchesResult, origFuncName) {
    assert(babel.isBlockStatement(functionNode.body), "the function node must be a block statement");
    functionNode.body.body.push(core_1.types.returnStatement(callHookExpression(matchesResult.replaceHooks[0], functionNode.params, [core_1.types.identifier(origFuncName)])));
}
function addBeforeHooks(functionNode, matchesResult) {
    for (const beforeHook of matchesResult.beforeHooks.reverse()) {
        functionNode.body.body.unshift(core_1.types.expressionStatement(callHookExpression(beforeHook, functionNode.params)));
    }
}
function assert(value, message) {
    if (!value) {
        throw new Error(message);
    }
}
function createInternalFunctionFromBody(name, params, body) {
    return core_1.types.variableDeclaration("const", [
        core_1.types.variableDeclarator(core_1.types.identifier(name), core_1.types.arrowFunctionExpression(params, body)),
    ]);
}
function callHookExpression(hook, params, additionalParams = []) {
    const id = hooking_1.hookManager.hookIndex(hook);
    const hookArgs = [
        core_1.types.numericLiteral(id),
        core_1.types.thisExpression(),
        core_1.types.arrayExpression(params),
    ];
    if (additionalParams.length !== 0) {
        hookArgs.push(...additionalParams);
    }
    return core_1.types.callExpression(core_1.types.memberExpression(core_1.types.identifier("HookManager"), core_1.types.identifier("callHook")), hookArgs);
}
function asyncHookThenExpression(hook, params, thenValue) {
    return core_1.types.functionExpression(null, [thenValue], core_1.types.blockStatement([
        core_1.types.expressionStatement(callHookExpression(hook, params, [thenValue])),
        core_1.types.returnStatement(thenValue),
    ]));
}
function callOriginalFunctionExpression(name, params) {
    return core_1.types.callExpression(core_1.types.memberExpression(core_1.types.identifier(name), core_1.types.identifier("call")), [core_1.types.thisExpression(), ...params]);
}
//# sourceMappingURL=functionHooks.js.map