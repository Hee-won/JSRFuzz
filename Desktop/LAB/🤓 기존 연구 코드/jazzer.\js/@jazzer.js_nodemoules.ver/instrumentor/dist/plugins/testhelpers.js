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
Object.defineProperty(exports, "__esModule", { value: true });
exports.removeIndentation = exports.instrumentWith = exports.instrumentAndEvalWith = void 0;
const instrument_1 = require("../instrument");
function instrumentAndEvalWith(...plugins) {
    const instrument = instrumentWith(plugins);
    return (input, output) => eval(instrument(input, output));
}
exports.instrumentAndEvalWith = instrumentAndEvalWith;
function instrumentWith(...plugins) {
    return (input, output) => expectInstrumentation(plugins, input, output);
}
exports.instrumentWith = instrumentWith;
function expectInstrumentation(plugins, input, output) {
    const code = removeIndentation(input);
    const instrumentor = new instrument_1.Instrumentor();
    const result = instrumentor.transform("test.js", code, plugins)?.code || code;
    expect(removeIndentation(result)).toBe(removeIndentation(output));
    return result;
}
function removeIndentation(text) {
    return text ? text.replace(/^\s*\|/gm, "").replace(/^\s*[\n\r]+/gm, "") : "";
}
exports.removeIndentation = removeIndentation;
//# sourceMappingURL=testhelpers.js.map