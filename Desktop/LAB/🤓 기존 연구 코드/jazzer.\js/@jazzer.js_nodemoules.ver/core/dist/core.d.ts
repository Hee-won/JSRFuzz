import * as libCoverage from "istanbul-lib-coverage";
import * as fuzzer from "@jazzer.js/fuzzer";
import * as hooking from "@jazzer.js/hooking";
import { Instrumentor } from "@jazzer.js/instrumentor";
import { Options } from "./options";
export declare enum FuzzingExitCode {
    Ok = 0,
    Finding = 77,
    UnexpectedError = 78
}
export type FindingAwareFuzzTarget = fuzzer.FuzzTarget & {
    __brand: "FindingAwareFuzzTarget";
};
export declare class FuzzingResult {
    readonly returnCode: FuzzingExitCode;
    readonly error?: unknown;
    constructor(returnCode: FuzzingExitCode, error?: unknown);
}
declare global {
    var Fuzzer: fuzzer.Fuzzer;
    var HookManager: hooking.HookManager;
    var __coverage__: libCoverage.CoverageMapData;
    var options: Options;
}
export declare function initFuzzing(options: Options): Promise<Instrumentor>;
export declare function registerGlobals(options: Options, globals?: any[]): void;
export declare function startFuzzing(options: Options): Promise<FuzzingResult>;
export declare function startFuzzingNoInit(fuzzFn: FindingAwareFuzzTarget, options: Options): Promise<FuzzingResult>;
/**
 * Wraps the given fuzz target function to handle errors from both the fuzz target and bug detectors.
 * Ensures that errors thrown by bug detectors have higher priority than errors in the fuzz target.
 */
export declare function asFindingAwareFuzzFn(originalFuzzFn: fuzzer.FuzzTarget, dumpCrashingInput?: boolean): FindingAwareFuzzTarget;
export * from "./api";
export { FuzzedDataProvider } from "./FuzzedDataProvider";
export { buildOptions, defaultOptions, Options, ParameterResolverIndex, setParameterResolverValue, } from "./options";
