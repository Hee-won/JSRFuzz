export type Thunk = () => void;
/**
 * Callbacks can be registered in fuzz targets or bug detectors to be executed
 * before or after each fuzz target invocation.
 */
export declare class Callbacks {
    private _afterEachCallbacks;
    private _beforeEachCallbacks;
    registerAfterEachCallback(callback: Thunk): void;
    registerBeforeEachCallback(callback: Thunk): void;
    runAfterEachCallbacks(): void;
    runBeforeEachCallbacks(): void;
}
export declare function getCallbacks(): Callbacks;
export declare function registerAfterEachCallback(callback: Thunk): void;
export declare function registerBeforeEachCallback(callback: Thunk): void;
