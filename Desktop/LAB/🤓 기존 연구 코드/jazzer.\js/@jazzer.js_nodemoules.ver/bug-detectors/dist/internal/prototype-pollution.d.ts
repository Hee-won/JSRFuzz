interface PrototypePollution {
    getProtoSnapshot: typeof getProtoSnapshot;
    detectPrototypePollution: typeof detectPrototypePollution;
    protoSnapshotsEqual: typeof protoSnapshotsEqual;
}
declare global {
    var PrototypePollution: PrototypePollution;
}
type BasicProtoSnapshots = ProtoSnapshot[];
type ProtoSnapshot = {
    prototype: any;
    propertyNames: string[];
    propertyValues: any[];
};
export declare function computeBasicPrototypeSnapshots(objects: any[]): BasicProtoSnapshots;
/**
 * Make a snapshot of the object's prototype.
 * The snapshot includes:
 * 1) the reference to the object's prototype.
 * 2) the names of the properties of the object's prototype (including function names).
 * 3) the values of the properties of the object's prototype (including functions).
 * @param obj - the object whose prototype we want to snapshot.
 */
declare function getProtoSnapshot(obj: any): ProtoSnapshot;
/**
 * Checks if the object's proto contains any non-function properties. Function properties are ignored.
 * @param obj The object to check.
 * @param identifier The identifier of the object (used for printing a useful finding message).
 * @param report Whether to report a finding if the object is a prototype pollution object.
 */
declare function detectPrototypePollution(obj: any, identifier?: string, report?: boolean): void;
/**
 * Checks if two prototype snapshots are equal. If they don't, throw a finding with a meaningful message.
 * @param snapshot1 The first prototype snapshot.
 * @param snapshot2 The second prototype snapshot.
 */
declare function protoSnapshotsEqual(snapshot1: ProtoSnapshot, snapshot2: ProtoSnapshot): string | undefined;
export {};
