"use strict";
/*
 * Copyright 2023 Code Intelligence GmbH
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.useDictionaryByParams = exports.addDictionary = exports.Dictionary = void 0;
const fs_1 = __importDefault(require("fs"));
const tmp_1 = __importDefault(require("tmp"));
const api_1 = require("./api");
/**
 * Dictionaries can be used to provide additional mutation suggestions to the
 * fuzzer.
 */
class Dictionary {
    _entries = [];
    get entries() {
        return [...this._entries];
    }
    addEntries(dictionary) {
        this._entries.push(...dictionary);
    }
}
exports.Dictionary = Dictionary;
function getDictionary() {
    return (0, api_1.getOrSetJazzerJsGlobal)("dictionary", new Dictionary());
}
function addDictionary(...dictionary) {
    getDictionary().addEntries(dictionary);
}
exports.addDictionary = addDictionary;
function useDictionaryByParams(options) {
    const opts = [...options];
    const dictionary = getDictionary().entries;
    // This diverges from the libFuzzer behavior, which allows only one dictionary (the last one).
    // We merge all dictionaries into one and pass that to libfuzzer.
    for (const option of options) {
        if (option.startsWith("-dict=")) {
            const dict = option.substring(6);
            // Preserve the filename in a comment before merging dictionary contents.
            dictionary.push(`\n# ${dict}:`);
            dictionary.push(fs_1.default.readFileSync(dict).toString());
        }
    }
    if (dictionary.length > 0) {
        // Add a comment to the top of the dictionary file.
        dictionary.unshift("# This file was automatically generated. Do not edit.");
        const content = dictionary.join("\n");
        // Use a temporary dictionary file to pass in the merged dictionaries.
        const dictFile = tmp_1.default.fileSync({
            mode: 0o700,
            prefix: "jazzer.js",
            postfix: "dict",
        });
        fs_1.default.writeFileSync(dictFile.name, content);
        fs_1.default.closeSync(dictFile.fd);
        opts.push("-dict=" + dictFile.name);
    }
    return opts;
}
exports.useDictionaryByParams = useDictionaryByParams;
//# sourceMappingURL=dictionary.js.map