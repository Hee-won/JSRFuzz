import { addon } from "./addon";
import { CoverageTracker } from "./coverage";
import { Tracer } from "./trace";
export type { FuzzTarget, FuzzTargetAsyncOrValue, FuzzTargetCallback, } from "./addon";
export interface Fuzzer {
    coverageTracker: CoverageTracker;
    tracer: Tracer;
    startFuzzing: typeof addon.startFuzzing;
    startFuzzingAsync: typeof addon.startFuzzingAsync;
    printAndDumpCrashingInput: typeof addon.printAndDumpCrashingInput;
    printReturnInfo: typeof addon.printReturnInfo;
}
export declare const fuzzer: Fuzzer;
export type { CoverageTracker } from "./coverage";
export type { Tracer } from "./trace";
