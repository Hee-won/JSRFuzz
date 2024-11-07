import { BabelFileResult, PluginItem, TransformOptions } from "@babel/core";
import { EdgeIdStrategy } from "./edgeIdStrategy";
import { SourceMap, SourceMapRegistry } from "./SourceMapRegistry";
export { instrumentationGuard } from "./guard";
export { registerInstrumentationPlugin } from "./plugin";
export { EdgeIdStrategy, FileSyncIdStrategy, MemorySyncIdStrategy, } from "./edgeIdStrategy";
export { SourceMap } from "./SourceMapRegistry";
export declare class Instrumentor {
    private readonly includes;
    private readonly excludes;
    private readonly customHooks;
    private readonly shouldCollectSourceCodeCoverage;
    private readonly isDryRun;
    private readonly idStrategy;
    private readonly sourceMapRegistry;
    constructor(includes?: string[], excludes?: string[], customHooks?: string[], shouldCollectSourceCodeCoverage?: boolean, isDryRun?: boolean, idStrategy?: EdgeIdStrategy, sourceMapRegistry?: SourceMapRegistry);
    init(): () => void;
    instrument(code: string, filename: string, sourceMap?: SourceMap): BabelFileResult | null;
    private asInputSourceOption;
    transform(filename: string, code: string, plugins: PluginItem[], options?: TransformOptions): BabelFileResult | null;
    private unloadInternalModules;
    shouldInstrumentForFuzzing(filepath: string): boolean;
    private shouldCollectCodeCoverage;
    private static doesMatchFilters;
    private static cleanup;
}
export declare function registerInstrumentor(instrumentor: Instrumentor): void;
