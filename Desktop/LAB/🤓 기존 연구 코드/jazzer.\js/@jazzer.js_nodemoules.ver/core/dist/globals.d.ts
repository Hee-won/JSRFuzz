declare global {
    var JazzerJS: Map<string, unknown> | undefined;
}
export declare const jazzerJs: Map<string, unknown>;
export declare function setJazzerJsGlobal<T>(name: string, value: T): void;
export declare function getJazzerJsGlobal<T>(name: string): T | undefined;
export declare function getOrSetJazzerJsGlobal<T>(name: string, defaultValue: T): T;
