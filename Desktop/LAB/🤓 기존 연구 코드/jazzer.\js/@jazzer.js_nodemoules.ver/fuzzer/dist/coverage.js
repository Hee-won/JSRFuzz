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
exports.coverageTracker = exports.CoverageTracker = void 0;
const addon_1 = require("./addon");
class CoverageTracker {
    static MAX_NUM_COUNTERS = 1 << 20;
    static INITIAL_NUM_COUNTERS = 1 << 9;
    coverageMap;
    currentNumCounters;
    constructor() { // CoverageTracker 클래스가 인스턴스화될 때 실행되는 특수한 메서드
        this.coverageMap = Buffer.alloc(CoverageTracker.MAX_NUM_COUNTERS, 0);
        this.currentNumCounters = CoverageTracker.INITIAL_NUM_COUNTERS;
        addon_1.addon.registerCoverageMap(this.coverageMap); 
        // 수집된 커버리지 정보 전달
        addon_1.addon.registerNewCounters(0, this.currentNumCounters);
    }
    enlargeCountersBufferIfNeeded(nextEdgeId) {
        // Enlarge registered counters if needed
        let newNumCounters = this.currentNumCounters;
        while (nextEdgeId >= newNumCounters) {
            newNumCounters = 2 * newNumCounters;
            if (newNumCounters > CoverageTracker.MAX_NUM_COUNTERS) {
                throw new Error(`Maximum number (${CoverageTracker.MAX_NUM_COUNTERS}) of coverage counts exceeded.`);
            }
        }
        // Register new counters if enlarged
        if (newNumCounters > this.currentNumCounters) {
            addon_1.addon.registerNewCounters(this.currentNumCounters, newNumCounters);
            this.currentNumCounters = newNumCounters;
            console.error(`INFO: New number of coverage counters ${this.currentNumCounters}`);
        }
    }
    /**
     * 지정된 ID의 커버리지 카운터를 늘립니다.
     * Increments the coverage counter for a given ID.
     * This function implements the NeverZero policy from AFL++.
     * See https://aflplus.plus//papers/aflpp-woot2020.pdf
     * @param edgeId the edge ID of the coverage counter to increment
     */
    incrementCounter(edgeId) {
        const counter = this.coverageMap.readUint8(edgeId);
        this.coverageMap.writeUint8(counter == 255 ? 1 : counter + 1, edgeId);
    }
    readCounter(edgeId) {
        return this.coverageMap.readUint8(edgeId);
    }
}
exports.CoverageTracker = CoverageTracker;
exports.coverageTracker = new CoverageTracker();
//# sourceMappingURL=coverage.js.map