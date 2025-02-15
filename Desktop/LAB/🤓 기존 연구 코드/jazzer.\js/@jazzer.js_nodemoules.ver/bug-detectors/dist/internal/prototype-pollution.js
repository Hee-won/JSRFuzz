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
Object.defineProperty(exports, "__esModule", { value: true });
exports.computeBasicPrototypeSnapshots = void 0;
const vm = __importStar(require("vm"));
const core_1 = require("@babel/core");
const core_2 = require("@jazzer.js/core");
const configuration_1 = require("../configuration");
// Allow the user to configure this bug detector in the custom-hooks file (if any).
class PrototypePollutionConfig {
    _excludedExactMatches = [];
    _instrumentAssignments = false;
    /**
     * Excludes one specific value of the `__proto__` property from being reported as a Prototype Pollution finding.
     * This is only relevant when instrumenting assignment expressions and variable declarations.
     * @param protoValue - stringified value of the `__proto__` for which no finding should be reported.
     */
    addExcludedExactMatch(protoValue) {
        this._excludedExactMatches.push(protoValue);
        return this;
    }
    /**
     * Enables instrumentation of assignment expressions and variable declarations.
     * This is a costly operation that might find non-global Prototype Pollution.
     * However, it also might result in false positives. Use `addExcludedExactMatch`
     * to exclude specific values from being reported as Prototype Pollution findings.
     *
     * @example
     * For the protobufjs library, you might add this to your custom-hooks file:
     * ```
     * getBugDetectorConfiguration("prototype-pollution")
     *    ?.instrumentAssignmentsAndVariableDeclarations()
     *    ?.addExcludedExactMatch('{"methods":{}}')
     *    ?.addExcludedExactMatch{'{"fields":{}}'");
     * ```
     */
    instrumentAssignmentsAndVariableDeclarations() {
        if (global.options.dryRun) {
            console.error("ERROR: " +
                "[Prototype Pollution Configuration] The configuration option " +
                "instrumentAssignmentsAndVariableDeclarations() is not supported in dry run mode.\n" +
                "  Either disable dry-run mode or remove this option from custom hooks.\n" +
                "  Jazzer.js initial arguments:", global.options);
            // We do not accept conflicting configuration options: abort.
            process.exit(1);
        }
        this._instrumentAssignments = true;
        return this;
    }
    getExcludedExactMatches() {
        return this._excludedExactMatches;
    }
    getInstrumentAssignmentsAndVariableDeclarations() {
        return this._instrumentAssignments;
    }
}
const config = new PrototypePollutionConfig();
// Add this bug detector's config to the global config map.
configuration_1.bugDetectorConfigurations.set("prototype-pollution", config);
// Make these functions available to instrumentation plugins and the user via the global object.
globalThis.PrototypePollution = {
    getProtoSnapshot: getProtoSnapshot,
    detectPrototypePollution: detectPrototypePollution,
    protoSnapshotsEqual: protoSnapshotsEqual,
};
(0, core_2.registerInstrumentationPlugin)(() => {
    function getIdentifierFromAssignmentExpression(expr) {
        if (core_1.types.isIdentifier(expr.left)) {
            return expr.left;
        }
        return skipMemberExpressions(expr.left);
    }
    function skipMemberExpressions(expr) {
        if (core_1.types.isIdentifier(expr)) {
            return expr;
        }
        else if (core_1.types.isMemberExpression(expr) && expr.object) {
            return skipMemberExpressions(expr.object);
        }
    }
    return {
        // This does not help with the case where a prototype of an object is first assigned to a variable which is then
        // used to pollute the prototype. However, as soon as a new object is created, the prototype is copied, and we will
        // detect the pollution. We probably need to check the scope and track such assignments.
        visitor: {
            // Wraps assignment expression in a lambda, and checks if __proto__ of the identifier contains any non-function values.
            // For example, the expression "a = 10;" will be transpiled to:
            // "((_unused0) => {
            // 	  PrototypePollution.detectPrototypePollution(a, "a");
            // 	  return a;
            // })(a = 10);"
            // This expression will be further instrumented by the regular Jazzer.js instrumentation plugins.
            AssignmentExpression(path) {
                if (!config ||
                    !config.getInstrumentAssignmentsAndVariableDeclarations()) {
                    return;
                }
                if (core_2.instrumentationGuard.has("AssignmentExpression", path.node)) {
                    return;
                }
                // Get identifier of the variable being assigned to
                const identifier = getIdentifierFromAssignmentExpression(path.node);
                if (!identifier) {
                    return;
                }
                // Copy the original assignment expression since we will replace it.
                const originalAssignment = JSON.parse(JSON.stringify(path.node));
                // Add the original assignment to the instrumentation guard to avoid its re-instrumentation.
                core_2.instrumentationGuard.add("AssignmentExpression", originalAssignment);
                path.replaceWith(core_1.types.callExpression(core_1.types.arrowFunctionExpression([path.scope.generateUidIdentifier("unused")], core_1.types.blockStatement([
                    core_1.types.expressionStatement(core_1.types.callExpression(core_1.types.identifier("PrototypePollution.detectPrototypePollution"), [identifier, core_1.types.stringLiteral("" + identifier.name)])),
                    // Return the result of the original assignment.
                    core_1.types.returnStatement(identifier),
                ])), [originalAssignment]));
            },
            // Wraps variable declaration in a lambda, and checks if __proto__ of the identifier contains any non-function properties.
            // For example: "const a = 10;" will be transpiled to:
            // "const a = ((_jazzerPP_a0) => {
            //           PrototypePollution.detectPrototypePollution(_jazzerPP_a0, "a");
            //           return _jazzerPP0;
            //         })(10);"
            // This expression will be further instrumented by the regular Jazzer.js instrumentation plugins.
            VariableDeclarator(path) {
                if (!config ||
                    !config.getInstrumentAssignmentsAndVariableDeclarations()) {
                    return;
                }
                if (path.node.init) {
                    if (core_2.instrumentationGuard.has("VariableDeclaration", path.node)) {
                        return;
                    }
                    const variableName = path.node.id.name;
                    const newVariable = path.scope.generateUidIdentifier("jazzerPP_" + variableName);
                    if (core_1.types.isAssignmentExpression(path.node.init))
                        core_2.instrumentationGuard.add("AssignmentExpression", path.node.init);
                    path.node.init = core_1.types.callExpression(core_1.types.arrowFunctionExpression([newVariable], core_1.types.blockStatement([
                        core_1.types.expressionStatement(core_1.types.callExpression(core_1.types.identifier("PrototypePollution.detectPrototypePollution"), [newVariable, core_1.types.stringLiteral("" + variableName)])),
                        // return the original initializer
                        core_1.types.returnStatement(newVariable),
                    ])), [path.node.init]);
                    core_2.instrumentationGuard.add("VariableDeclaration", path.node.init);
                }
            },
        },
    };
});
// These objects will be used to detect prototype pollution.
// Using global arrays for performance reasons.
let BASIC_OBJECTS = [
    {},
    [],
    "",
    42,
    true,
    () => {
        /**/
    },
];
// The names are used in the Findings to print nicer messages.
const BASIC_OBJECT_NAMES = [
    "Object",
    "Array",
    "String",
    "Number",
    "Boolean",
    "Function",
];
// Compute prototype snapshots of each selected basic object before any fuzz tests are run.
// These snapshots are used to detect prototype pollution after each fuzz test.
let BASIC_PROTO_SNAPSHOTS = computeBasicPrototypeSnapshots(BASIC_OBJECTS);
if ((0, core_2.getJazzerJsGlobal)("vmContext")) {
    const vmContext = (0, core_2.getJazzerJsGlobal)("vmContext");
    Object.defineProperty(vmContext, "PrototypePollution", {
        value: PrototypePollution,
        writable: false,
        enumerable: true,
        configurable: false,
    });
    // Get the basic objects from the vm context.
    // TODO: This should be updated every time Jest sacks the current vm context.
    BASIC_OBJECTS = vm.runInContext('[{},[],"",42,true,()=>{}]', vmContext);
    BASIC_PROTO_SNAPSHOTS = computeBasicPrototypeSnapshots(BASIC_OBJECTS);
}
function computeBasicPrototypeSnapshots(
// eslint-disable-next-line @typescript-eslint/no-explicit-any
objects) {
    // These objects will be used to detect prototype pollution.
    // Using global arrays for performance reasons.
    return objects.map(getProtoSnapshot);
}
exports.computeBasicPrototypeSnapshots = computeBasicPrototypeSnapshots;
/**
 * Make a snapshot of the object's prototype.
 * The snapshot includes:
 * 1) the reference to the object's prototype.
 * 2) the names of the properties of the object's prototype (including function names).
 * 3) the values of the properties of the object's prototype (including functions).
 * @param obj - the object whose prototype we want to snapshot.
 */
// eslint-disable-next-line  @typescript-eslint/no-explicit-any
function getProtoSnapshot(obj) {
    const prototype = Object.getPrototypeOf(obj);
    const propertyNames = Object.getOwnPropertyNames(prototype);
    // eslint-disable-next-line  @typescript-eslint/no-explicit-any
    const propertyValues = new Array(propertyNames.length);
    try {
        for (let i = 0; i < propertyNames.length; i++) {
            propertyValues[i] = prototype[propertyNames[i]];
        }
    }
    catch (e) {
        // ignore
    }
    return {
        prototype: prototype,
        propertyNames: propertyNames,
        propertyValues: propertyValues,
    };
}
(0, core_2.registerAfterEachCallback)(function detectPrototypePollution() {
    detectPrototypePollutionOfBasicObjects(BASIC_PROTO_SNAPSHOTS, BASIC_OBJECTS);
});
function detectPrototypePollutionOfBasicObjects(initialSnapshots, objects) {
    const currentProtoSnapshots = computeBasicPrototypeSnapshots(objects);
    // Compare the current prototype snapshots of basic objects to the original ones.
    for (let i = 0; i < initialSnapshots.length; i++) {
        if (!currentProtoSnapshots[i]) {
            (0, core_2.reportFinding)(`Prototype Pollution: Prototype of ${BASIC_OBJECT_NAMES[i]} changed.`, false);
            return;
        }
        const equalityResult = protoSnapshotsEqual(initialSnapshots[i], currentProtoSnapshots[i]);
        if (equalityResult) {
            (0, core_2.reportFinding)(`Prototype Pollution: Prototype of ${BASIC_OBJECT_NAMES[i]} changed. ${equalityResult}`, false);
            return;
        }
    }
}
// There are two main ways to pollute a prototype of an object:
// 1. Changing a prototype's property using __proto__
// 2. Changing a prototype's property using constructor.prototype
// This dictionary adds these strings to the fuzzer dictionary.
// Adding strings targeted at specific protocols (XML, HTTP, protobuf, etc.) will reduce the performance of the fuzzer,
// because it will try strings from the wrong protocol. Therefore, it is advised to add protocol-specific strings
// to the user dictionary for each fuzz test individually.
(0, core_2.addDictionary)('"__proto__"', '"constructor"', '"prototype"', '"constructor.prototype"');
/**
 * Checks if the object's proto contains any non-function properties. Function properties are ignored.
 * @param obj The object to check.
 * @param identifier The identifier of the object (used for printing a useful finding message).
 * @param report Whether to report a finding if the object is a prototype pollution object.
 */
function detectPrototypePollution(
// eslint-disable-next-line  @typescript-eslint/no-explicit-any
obj, identifier, report = true) {
    while (obj !== undefined && obj !== null) {
        try {
            // JSON.stringify will ignore function properties.
            const protoValue = JSON.stringify(Object.getPrototypeOf(obj));
            if (protoValue &&
                !(protoValue === "null" ||
                    protoValue === "{}" ||
                    protoValue === "[]" ||
                    protoValue === '""' ||
                    protoValue === "false" ||
                    protoValue === "true" ||
                    protoValue === "0" ||
                    // User-defined pollution strings are whitelisted here.
                    config?.getExcludedExactMatches()?.includes(protoValue))) {
                let message;
                if (identifier) {
                    message = `Prototype Pollution: ${identifier}.__proto__ value is ${protoValue}`;
                }
                else {
                    message = `Prototype Pollution: __proto__ value is ${protoValue}`;
                }
                if (report) {
                    (0, core_2.reportAndThrowFinding)(message);
                }
                // If prototype pollution is detected, always stop analyzing the prototype chain.
                return;
            }
        }
        catch (e) {
            // Ignored.
        }
        // Get the same data from the object's prototype.
        obj = Object.getPrototypeOf(obj);
    }
}
/**
 * Checks if two prototype snapshots are equal. If they don't, throw a finding with a meaningful message.
 * @param snapshot1 The first prototype snapshot.
 * @param snapshot2 The second prototype snapshot.
 */
// This is used for basic objects, such as {}, [], Function, number, string.
function protoSnapshotsEqual(snapshot1, snapshot2) {
    if (snapshot1.prototype !== snapshot2.prototype) {
        return `Different [[Prototype]]: ${snapshot1.prototype} vs ${snapshot2.prototype}`;
    }
    if (snapshot1.propertyNames.length !== snapshot2.propertyNames.length) {
        const printNamesAndValues = (names, values) => {
            const namesAndValues = names
                .map((name, index) => `'${name}': ${values[index]}`)
                .join(", ");
            return "{ " + namesAndValues + " }";
        };
        // The number of properties has changed: assemble a meaningful message to
        // the user stating which properties are missing/extra for each prototype object.
        // Get the complement of propertyNames.
        const complement1 = snapshot1.propertyNames.filter((x) => !snapshot2.propertyNames.includes(x));
        const complement2 = snapshot2.propertyNames.filter((x) => !snapshot1.propertyNames.includes(x));
        // Get corresponding snapshot1.propertyValues
        const complement1Values = complement1.map((name) => snapshot1.propertyValues[snapshot1.propertyNames.indexOf(name)]);
        const complement2Values = complement2.map((name) => snapshot2.propertyValues[snapshot2.propertyNames.indexOf(name)]);
        let message = "";
        if (complement1.length > 0) {
            message +=
                "Additional properties in object0: " +
                    printNamesAndValues(complement1, complement1Values);
        }
        if (complement2.length > 0) {
            message +=
                "Additional properties in object1: " +
                    printNamesAndValues(complement2, complement2Values);
        }
        return message;
    }
    // Lengths are the same, now we can compare the property names.
    for (let propertyId = 0; propertyId < snapshot1.propertyNames.length; propertyId++) {
        if (snapshot1.propertyNames[propertyId] !==
            snapshot2.propertyNames[propertyId]) {
            return `Different or rearranged property names: ${snapshot1.propertyNames[propertyId]} vs. ${snapshot2.propertyNames[propertyId]}`;
        }
    }
    // Property names are the same, now we can compare the values.
    for (let propertyId = 0; propertyId < snapshot1.propertyValues.length; propertyId++) {
        if (snapshot1.propertyValues[propertyId] !==
            snapshot2.propertyValues[propertyId]) {
            return `Different properties: ${snapshot1.propertyNames[propertyId]}: ${snapshot1.propertyValues[propertyId]} vs. 
${snapshot2.propertyNames[propertyId]}: ${snapshot2.propertyValues[propertyId]}`;
        }
    }
}
//# sourceMappingURL=prototype-pollution.js.map