/**
 * Dictionaries can be used to provide additional mutation suggestions to the
 * fuzzer.
 */
export declare class Dictionary {
    private _entries;
    get entries(): string[];
    addEntries(dictionary: string[]): void;
}
export declare function addDictionary(...dictionary: string[]): void;
export declare function useDictionaryByParams(options: string[]): string[];
