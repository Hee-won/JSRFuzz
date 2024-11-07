export declare class Finding extends Error {
}
export declare class FuzzerSignalFinding extends Finding {
    readonly exitCode: number;
    constructor(signal: number);
}
export declare function clearFirstFinding(): Finding | undefined;
/**
 * Save the first finding reported by any bug detector.
 *
 * @param cause - The finding to be reported.
 * @param containStack - Whether the finding should contain a stack trace or not.
 */
export declare function reportFinding(cause: string | Finding, containStack?: boolean): Finding | undefined;
/**
 * Save the first finding reported by any bug detector and throw it to
 * potentially abort the current execution.
 *
 * @param cause - The finding to be saved and thrown.
 * @param containStack - Whether the finding should contain a stack trace or not.
 */
export declare function reportAndThrowFinding(cause: string | Finding, containStack?: boolean): void | never;
/**
 * Prints a finding, or more generally some kind of error, to stderr.
 */
export declare function printFinding(error: unknown, print?: (msg: string) => void): void;
export declare function cleanErrorStack(error: unknown): void;
export declare function errorName(error: unknown): string;
