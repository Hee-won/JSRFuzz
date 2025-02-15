/**
 * Jazzer.js options structure expected by the fuzzer.
 *
 * Entry functions, like the CLI or test framework integrations, need to build
 * this structure and should use the same property names for exposing their own
 * options.
 */
export interface Options {
    fuzzTarget: string;
    fuzzEntryPoint: string;
    includes: string[];
    excludes: string[];
    dryRun: boolean;
    sync: boolean;
    fuzzerOptions: string[];
    customHooks: string[];
    expectedErrors: string[];
    timeout: number;
    idSyncFile?: string;
    coverage: boolean;
    coverageDirectory: string;
    coverageReporters: string[];
    disableBugDetectors: string[];
    mode: "fuzzing" | "regression";
    verbose?: boolean;
}
export declare const defaultOptions: Options;
export type KeyFormatSource = (key: string) => string;
export declare const fromCamelCase: KeyFormatSource;
export declare const fromSnakeCase: KeyFormatSource;
export declare const fromSnakeCaseWithPrefix: (prefix: string) => KeyFormatSource;
export declare enum ParameterResolverIndex {
    DefaultOptions = 1,
    ConfigurationFile = 2,
    EnvironmentVariables = 3,
    CommandLineArguments = 4
}
/**
 * Set the value object of a parameter resolver. Every resolver expects value
 * object parameter names in a specific format, e.g. camel case or snake case,
 * see the resolver definitions for details.
 */
export declare function setParameterResolverValue(index: ParameterResolverIndex, inputs: Partial<Options>): void;
/**
 * Build a complete `Option` object based on the parameter resolver chain.
 * Add externally passed in values via the `setParameterResolverValue` function,
 * before calling `buildOptions`.
 */
export declare function buildOptions(): Options;
export declare function buildFuzzerOption(options: Options): string[];
export declare function spawnsSubprocess(fuzzerOptions: string[]): boolean;
