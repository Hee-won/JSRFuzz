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
const core_1 = require("@jazzer.js/core");
const hooking_1 = require("@jazzer.js/hooking");
/**
 * Importing this file adds "before-hooks" for all functions in the built-in `fs`, `fs/promises`, and `path` module and guides
 * the fuzzer towards the uniquely chosen `goal` string `"../../jaz_zer"`. If the goal is found in the first argument
 * of any hooked function, a `Finding` is reported.
 */
const goal = "../../jaz_zer";
const modulesToHook = [
    {
        moduleName: "fs",
        functionNames: [
            "access",
            "accessSync",
            "appendFile",
            "appendFileSync",
            "chmod",
            "chown",
            "chownSync",
            "chmodSync",
            "createReadStream",
            "createWriteStream",
            "exists",
            "existsSync",
            "lchmod",
            "lchmodSync",
            "lchown",
            "lchownSync",
            "lstat",
            "lstatSync",
            "lutimes",
            "lutimesSync",
            "mkdir",
            "mkdirSync",
            "open",
            "opendir",
            "opendirSync",
            "openAsBlob",
            "openSync",
            "readFile",
            "readFileSync",
            "readlink",
            "readlinkSync",
            "readdir",
            "readdirSync",
            "realpath",
            "realpathSync",
            "rm",
            "rmSync",
            "rmdir",
            "rmdirSync",
            "stat",
            "statfs",
            "statfsSync",
            "statSync",
            "truncate",
            "truncateSync",
            "unlink",
            "unlinkSync",
            "unwatchFile",
            "utimes",
            "utimesSync",
            "watch",
            "watchFile",
            "writeFile",
            "writeFileSync",
        ],
    },
    {
        moduleName: "fs/promises",
        functionNames: [
            "access",
            "appendFile",
            "chmod",
            "chown",
            "lchmod",
            "lchown",
            "lstat",
            "lutimes",
            "mkdir",
            "open",
            "opendir",
            "readFile",
            "readlink",
            "readdir",
            "realpath",
            "rm",
            "rmdir",
            "stat",
            "statfs",
            "truncate",
            "unlink",
            "utimes",
            "watch",
            "writeFile",
        ],
    },
    // path.join() can have any number of strings as inputs. Internally, it uses path.normalize(), which we hook here.
    {
        moduleName: "path",
        functionNames: ["normalize", "resolve"],
    },
];
for (const module of modulesToHook) {
    for (const functionName of module.functionNames) {
        const beforeHook = (thisPtr, params, hookId) => {
            if (params === undefined || params.length === 0) {
                return;
            }
            // The first argument of the original function is typically
            // a path or a file name. For some functions, it can be a URL or a Buffer.
            detectFindingAndGuideFuzzing(params[0], goal, hookId, functionName);
        };
        (0, hooking_1.registerBeforeHook)(functionName, module.moduleName, false, beforeHook);
    }
}
// Some functions have two arguments that can be used for path traversal.
const functionsWithTwoTargets = [
    {
        moduleName: "fs/promises",
        functionNames: ["copyFile", "cp", "link", "rename", "symlink"],
    },
    {
        moduleName: "fs",
        functionNames: [
            "copyFile",
            "copyFileSync",
            "cp",
            "cpSync",
            "link",
            "linkSync",
            "rename",
            "renameSync",
            "symlink",
            "symlinkSync",
        ],
    },
];
for (const module of functionsWithTwoTargets) {
    for (const functionName of module.functionNames) {
        const makeBeforeHook = (extraHookId) => {
            return (thisPtr, params, hookId) => {
                if (params === undefined || params.length < 2) {
                    return;
                }
                // We don't want to confuse the fuzzer guidance with the same hookId for both function arguments.
                // Therefore, we use an extra hookId for the second argument.
                detectFindingAndGuideFuzzing(params[0], goal, hookId, functionName);
                detectFindingAndGuideFuzzing(params[1], goal, extraHookId, functionName);
            };
        };
        (0, hooking_1.registerBeforeHook)(functionName, module.moduleName, false, makeBeforeHook((0, hooking_1.callSiteId)(functionName, module.moduleName, "secondId")));
    }
}
function detectFindingAndGuideFuzzing(input, goal, hookId, functionName) {
    if (typeof input === "string" ||
        input instanceof URL ||
        input instanceof Buffer) {
        const argument = input.toString();
        if (argument.includes(goal)) {
            (0, core_1.reportAndThrowFinding)(`Path Traversal in ${functionName}(): called with '${argument}'`);
        }
        (0, core_1.guideTowardsContainment)(argument, goal, hookId);
    }
}
//# sourceMappingURL=path-traversal.js.map