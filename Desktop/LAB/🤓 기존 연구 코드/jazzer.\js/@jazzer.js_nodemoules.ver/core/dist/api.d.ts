export { registerInstrumentationPlugin, instrumentationGuard, } from "@jazzer.js/instrumentor";
export { registerAfterEachCallback, registerBeforeEachCallback, } from "./callback";
export { addDictionary } from "./dictionary";
export { reportAndThrowFinding, reportFinding } from "./finding";
export { getJazzerJsGlobal, setJazzerJsGlobal, getOrSetJazzerJsGlobal, } from "./globals";
export declare const guideTowardsEquality: (current: string, target: string, id: number) => void;
export declare const guideTowardsContainment: (needle: string, haystack: string, id: number) => void;
export declare const exploreState: typeof import("packages/fuzzer/dist/trace").exploreState;
export declare const jazzer: {
    guideTowardsEquality: (current: string, target: string, id: number) => void;
    guideTowardsContainment: (needle: string, haystack: string, id: number) => void;
    exploreState: typeof import("packages/fuzzer/dist/trace").exploreState;
};
