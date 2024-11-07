/// <reference types="node" />
export type FuzzTargetAsyncOrValue = (data: Buffer) => unknown | Promise<unknown>;
export type FuzzTargetCallback = (data: Buffer, done: (e?: Error) => void) => unknown;
export type FuzzTarget = FuzzTargetAsyncOrValue | FuzzTargetCallback;
export type FuzzOpts = string[];
export type StartFuzzingSyncFn = (fuzzFn: FuzzTarget, fuzzOpts: FuzzOpts, jsStopCallback: (signal: number) => void) => Promise<void>;
export type StartFuzzingAsyncFn = (fuzzFn: FuzzTarget, fuzzOpts: FuzzOpts) => Promise<void>;
type NativeAddon = {
    registerCoverageMap: (buffer: Buffer) => void;
    registerNewCounters: (oldNumCounters: number, newNumCounters: number) => void;
    traceUnequalStrings: (hookId: number, current: string, target: string) => void;
    traceStringContainment: (hookId: number, needle: string, haystack: string) => void;
    traceIntegerCompare: (hookId: number, current: number, target: number) => void;
    tracePcIndir: (hookId: number, state: number) => void;
    printAndDumpCrashingInput: () => void;
    printReturnInfo: (sync: boolean) => void;
    printVersion: () => void;
    startFuzzing: StartFuzzingSyncFn;
    startFuzzingAsync: StartFuzzingAsyncFn;
};
export declare const addon: NativeAddon;
export {};
