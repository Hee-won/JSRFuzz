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
exports.ZeroEdgeIdStrategy = exports.FileSyncIdStrategy = exports.MemorySyncIdStrategy = exports.IncrementingEdgeIdStrategy = void 0;
const fs = __importStar(require("fs"));
const os = __importStar(require("os"));
const process_1 = __importDefault(require("process"));
const lock = __importStar(require("proper-lockfile"));
const fuzzer_1 = require("@jazzer.js/fuzzer");
if (process_1.default.listeners) {
    // "signal-exit" library imported by "proper-lockfile" inserts listeners
    // for all important signals, such as SIGALRM and SIGINT
    // (see https://github.com/tapjs/signal-exit/blob/39a5946d2b04d00106400c0dcc5d358a40892438/signals.js)
    // libFuzzer has a SIGALRM handler to deal with -timeout flag, here we give
    // the control back to libFuzzer by removing the SIGALRM listeners inserted by "signal-exit".
    if (process_1.default.listeners("SIGALRM").length > 0) {
        process_1.default.removeListener("SIGALRM", process_1.default.listeners("SIGALRM")[0]);
    }
    // SIGINT: in synchronous mode, pressing CTRL-C does not abort the process.
    // Removing the SIGINT listener inserted by "signal-exit" gives the control back to the users.
    if (process_1.default.listeners("SIGINT").length > 0) {
        process_1.default.removeListener("SIGINT", process_1.default.listeners("SIGINT")[0]);
    }
}
class IncrementingEdgeIdStrategy {
    _nextEdgeId;
    constructor(_nextEdgeId) {
        this._nextEdgeId = _nextEdgeId;
    }
    nextEdgeId() {
        fuzzer_1.fuzzer.coverageTracker.enlargeCountersBufferIfNeeded(this._nextEdgeId);
        return this._nextEdgeId++;
    }
}
exports.IncrementingEdgeIdStrategy = IncrementingEdgeIdStrategy;
class MemorySyncIdStrategy extends IncrementingEdgeIdStrategy {
    constructor() {
        super(0);
    }
    startForSourceFile(filename) {
        // nothing to do here
    }
    commitIdCount(filename) {
        // nothing to do here
    }
}
exports.MemorySyncIdStrategy = MemorySyncIdStrategy;
/**
 * A strategy for edge ID generation that synchronizes the IDs assigned to a source file
 * with other processes via the specified `idSyncFile`. The edge information stored as a
 * line of the format: <source file path>,<initial edge ID>,<total edge count>
 *
 * This class takes care of synchronizing the access to the file between
 * multiple processes accessing it during instrumentation.
 */
class FileSyncIdStrategy extends IncrementingEdgeIdStrategy {
    idSyncFile;
    static fatalExitCode = 79;
    cachedIdCount;
    firstEdgeId;
    releaseLockOnSyncFile;
    constructor(idSyncFile) {
        super(0);
        this.idSyncFile = idSyncFile;
    }
    startForSourceFile(filename) {
        // We resort to busy waiting since the `Transformer` required by istanbul's `hookRequire`
        // must be a synchronous function returning the transformed code.
        for (;;) {
            const isLocked = lock.checkSync(this.idSyncFile);
            if (isLocked) {
                // If the ID sync file is already locked, wait for a random period of time
                // between 0 and 100 milliseconds. Waiting for different periods reduces
                // the chance of all processes wanting to acquire the lock at the same time.
                this.wait(this.randomIntFromInterval(0, 100));
                continue;
            }
            try {
                // Acquire the lock for the ID sync file and look for the initial edge ID and
                // corresponding number of inserted counters.
                this.releaseLockOnSyncFile = lock.lockSync(this.idSyncFile);
                const idInfo = fs
                    .readFileSync(this.idSyncFile, "utf8")
                    .toString()
                    .split(os.EOL)
                    .filter((line) => line.length !== 0)
                    .map((line) => {
                    const parts = line.split(",");
                    if (parts.length !== 3) {
                        lock.unlockSync(this.idSyncFile);
                        throw Error(`Expected ID file line to be of the form <source file>,<first ID>,<num IDs>", got "${line}"`);
                    }
                    return {
                        filename: parts[0],
                        firstId: parseInt(parts[1], 10),
                        idCount: parseInt(parts[2], 10),
                    };
                });
                const idInfoForFile = idInfo.filter((info) => info.filename === filename);
                switch (idInfoForFile.length) {
                    case 0:
                        // We are the first to encounter this source file and thus need to hold the lock
                        // until the file has been instrumented and we know the required number of edge IDs.
                        //
                        // Compute the next free ID as the maximum over the sums of first ID and ID count, starting at 0 if
                        // this is the first ID to be assigned. Since this is the only way new lines are added to
                        // the file, the maximum is always attained by the last line.
                        this.firstEdgeId =
                            idInfo.length !== 0
                                ? idInfo[idInfo.length - 1].firstId +
                                    idInfo[idInfo.length - 1].idCount
                                : 0;
                        break;
                    case 1:
                        // This source file has already been instrumented elsewhere, so we just return the first ID and
                        // ID count reported from there and release the lock right away. The caller is still expected
                        // to call commitIdCount.
                        this.firstEdgeId = idInfoForFile[0].firstId;
                        this.cachedIdCount = idInfoForFile[0].idCount;
                        this.releaseLockOnSyncFile();
                        break;
                    default:
                        this.releaseLockOnSyncFile();
                        console.error(`ERROR: Multiple entries for ${filename} in ID sync file`);
                        process_1.default.exit(FileSyncIdStrategy.fatalExitCode);
                }
                break;
            }
            catch (e) {
                // Retry to wait for the lock to be release it is acquired by another process
                // in the time window between last successful check and trying to acquire it.
                if (this.isLockAlreadyHeldError(e)) {
                    continue;
                }
                // Before rethrowing the exception, release the lock if we have already acquired it.
                if (this.releaseLockOnSyncFile !== undefined) {
                    this.releaseLockOnSyncFile();
                }
                // Stop waiting for the lock if we encounter other errors. Also, rethrow the error.
                throw e;
            }
        }
        this._nextEdgeId = this.firstEdgeId;
    }
    commitIdCount(filename) {
        if (this.firstEdgeId === undefined) {
            throw Error("commitIdCount() is called before startForSourceFile()");
        }
        const usedIdsCount = this._nextEdgeId - this.firstEdgeId;
        if (this.cachedIdCount !== undefined) {
            // We released the lock already in startForSourceFile since the file had already been instrumented
            // elsewhere. As we know the expected number of IDs for the current source file in this case, check
            // for deviations.
            if (this.cachedIdCount !== usedIdsCount) {
                throw Error(`${filename} has ${usedIdsCount} edges, but ${this.cachedIdCount} edges reserved in ID sync file`);
            }
        }
        else {
            if (this.releaseLockOnSyncFile === undefined) {
                console.error(`ERROR: Lock on ID sync file is not acquired by the first processing instrumenting: ${filename}`);
                process_1.default.exit(FileSyncIdStrategy.fatalExitCode);
            }
            // We are the first to instrument this file and should record the number of IDs in the sync file.
            fs.appendFileSync(this.idSyncFile, `${filename},${this.firstEdgeId},${usedIdsCount}${os.EOL}`);
            this.releaseLockOnSyncFile();
            this.releaseLockOnSyncFile = undefined;
            this.firstEdgeId = undefined;
            this.cachedIdCount = undefined;
        }
    }
    wait(timeout) {
        // This is a workaround to synchronously sleep for a `timout` milliseconds.
        // The static Atomics.wait() method verifies that a given position in an Int32Array
        // still contains a given value and if so sleeps, awaiting a wakeup or a timeout.
        // Here, we deliberately cause a timeout.
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, timeout);
    }
    randomIntFromInterval(min, max) {
        return Math.floor(Math.random() * (max - min + 1) + min);
    }
    isLockAlreadyHeldError(e) {
        return (e != null && typeof e === "object" && "code" in e && e.code === "ELOCKED");
    }
}
exports.FileSyncIdStrategy = FileSyncIdStrategy;
class ZeroEdgeIdStrategy {
    nextEdgeId() {
        return 0;
    }
    startForSourceFile(filename) {
        // Nothing to do here
    }
    commitIdCount(filename) {
        // Nothing to do here
    }
}
exports.ZeroEdgeIdStrategy = ZeroEdgeIdStrategy;
//# sourceMappingURL=edgeIdStrategy.js.map