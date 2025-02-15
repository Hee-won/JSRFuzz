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
exports.registerInstrumentor = exports.Instrumentor = exports.MemorySyncIdStrategy = exports.FileSyncIdStrategy = exports.registerInstrumentationPlugin = exports.instrumentationGuard = void 0;
const core_1 = require("@babel/core");
const istanbul_lib_hook_1 = require("istanbul-lib-hook");
const hooking_1 = require("@jazzer.js/hooking");
const edgeIdStrategy_1 = require("./edgeIdStrategy");
const plugin_1 = require("./plugin");
const codeCoverage_1 = require("./plugins/codeCoverage");
const compareHooks_1 = require("./plugins/compareHooks");
const functionHooks_1 = require("./plugins/functionHooks");
const sourceCodeCoverage_1 = require("./plugins/sourceCodeCoverage");
const SourceMapRegistry_1 = require("./SourceMapRegistry");
var guard_1 = require("./guard");
Object.defineProperty(exports, "instrumentationGuard", { enumerable: true, get: function () { return guard_1.instrumentationGuard; } });
var plugin_2 = require("./plugin");
Object.defineProperty(exports, "registerInstrumentationPlugin", { enumerable: true, get: function () { return plugin_2.registerInstrumentationPlugin; } });
var edgeIdStrategy_2 = require("./edgeIdStrategy");
Object.defineProperty(exports, "FileSyncIdStrategy", { enumerable: true, get: function () { return edgeIdStrategy_2.FileSyncIdStrategy; } });
Object.defineProperty(exports, "MemorySyncIdStrategy", { enumerable: true, get: function () { return edgeIdStrategy_2.MemorySyncIdStrategy; } });
class Instrumentor {
    includes;
    excludes;
    customHooks;
    shouldCollectSourceCodeCoverage;
    isDryRun;
    idStrategy;
    sourceMapRegistry;
    constructor(includes = [], excludes = [], customHooks = [], shouldCollectSourceCodeCoverage = false, isDryRun = false, idStrategy = new edgeIdStrategy_1.MemorySyncIdStrategy(), sourceMapRegistry = new SourceMapRegistry_1.SourceMapRegistry()) {
        this.includes = includes;
        this.excludes = excludes;
        this.customHooks = customHooks;
        this.shouldCollectSourceCodeCoverage = shouldCollectSourceCodeCoverage;
        this.isDryRun = isDryRun;
        this.idStrategy = idStrategy;
        this.sourceMapRegistry = sourceMapRegistry;
        // This is our default case where we want to include everything and exclude the "node_modules" folder.
        if (includes.length === 0 && excludes.length === 0) {
            includes.push("*");
            excludes.push("node_modules");
        }
        this.includes = Instrumentor.cleanup(includes);
        this.excludes = Instrumentor.cleanup(excludes);
    }
    init() {
        if (this.includes.includes("jazzer.js")) {
            this.unloadInternalModules();
        }
        return this.sourceMapRegistry.installSourceMapSupport();
    }
    instrument(code, filename, sourceMap) {
        // Extract inline source map from code string and use it as input source map
        // in further transformations.
        const inputSourceMap = sourceMap ?? (0, SourceMapRegistry_1.extractInlineSourceMap)(code);
        const transformations = [];
        const shouldInstrumentFile = this.shouldInstrumentForFuzzing(filename);
        if (shouldInstrumentFile) {
            transformations.push(...plugin_1.instrumentationPlugins.plugins, (0, codeCoverage_1.codeCoverage)(this.idStrategy), compareHooks_1.compareHooks);
        }
        if (hooking_1.hookManager.hasFunctionsToHook(filename)) {
            transformations.push((0, functionHooks_1.functionHooks)(filename));
        }
        if (this.shouldCollectCodeCoverage(filename)) {
            transformations.push((0, sourceCodeCoverage_1.sourceCodeCoverage)(filename, this.asInputSourceOption((0, SourceMapRegistry_1.toRawSourceMap)(inputSourceMap))));
        }
        if (shouldInstrumentFile) {
            this.idStrategy.startForSourceFile(filename);
        }
        const result = this.transform(filename, code, transformations, this.asInputSourceOption(inputSourceMap));
        if (shouldInstrumentFile) {
            this.idStrategy.commitIdCount(filename);
        }
        return result;
    }
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    asInputSourceOption(inputSourceMap) {
        // Empty input source maps mess up the coverage report.
        if (inputSourceMap) {
            return {
                inputSourceMap,
            };
        }
        return {};
    }
    transform(filename, code, plugins, options = {}) {
        if (plugins.length === 0) {
            return null;
        }
        const result = (0, core_1.transformSync)(code, {
            filename: filename,
            sourceFileName: filename,
            sourceMaps: true,
            plugins: plugins,
            ...options,
        });
        if (result?.map) {
            this.sourceMapRegistry.registerSourceMap(filename, result.map);
        }
        return result;
    }
    unloadInternalModules() {
        console.error("DEBUG: Unloading internal Jazzer.js modules for instrumentation...");
        [
            "@jazzer.js/bug-detectors",
            "@jazzer.js/core",
            "@jazzer.js/fuzzer",
            "@jazzer.js/hooking",
            "@jazzer.js/instrumentor",
            "@jazzer.js/jest-runner",
        ].forEach((module) => {
            delete require.cache[require.resolve(module)];
        });
    }
    shouldInstrumentForFuzzing(filepath) {
        return (!this.isDryRun &&
            Instrumentor.doesMatchFilters(filepath, this.includes, this.excludes));
    }
    shouldCollectCodeCoverage(filepath) {
        return (this.shouldCollectSourceCodeCoverage &&
            (Instrumentor.doesMatchFilters(filepath, this.includes, this.excludes) ||
                Instrumentor.doesMatchFilters(filepath, this.customHooks, ["nothing"])));
    }
    static doesMatchFilters(filepath, includes, excludes) {
        const included = includes.find((include) => filepath.includes(include)) !== undefined;
        const excluded = excludes.find((exclude) => filepath.includes(exclude)) !== undefined;
        return included && !excluded;
    }
    static cleanup(settings) {
        return settings
            .filter((setting) => setting)
            .map((setting) => (setting === "*" ? "" : setting)); // empty string matches every file
    }
}
exports.Instrumentor = Instrumentor;
function registerInstrumentor(instrumentor) {
    instrumentor.init();
    (0, istanbul_lib_hook_1.hookRequire)(() => true, (code, opts) => {
        return instrumentor.instrument(code, opts.filename)?.code || code;
    }, 
    // required to allow jest to run typescript files
    // jest's typescript integration will transform the typescript into javascript before giving it to the
    // instrumentor but the filename will still have a .ts extension
    { extensions: [".js", ".mjs", ".cjs", ".ts", ".mts", ".cts"] });
}
exports.registerInstrumentor = registerInstrumentor;
//# sourceMappingURL=instrument.js.map