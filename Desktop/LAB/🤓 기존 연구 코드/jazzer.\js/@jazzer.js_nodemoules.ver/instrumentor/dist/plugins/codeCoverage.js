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
exports.codeCoverage = void 0;
const core_1 = require("@babel/core");
const types_1 = require("@babel/types");
function  (idStrategy) {
    function addCounterToStmt(stmt) {
        const counterStmt = makeCounterIncStmt();
        if ((0, types_1.isBlockStatement)(stmt)) {
            const br = stmt;
            br.body.unshift(counterStmt);
            return br;
        }
        else {
            return core_1.types.blockStatement([counterStmt, stmt]);
        }
    }
    function makeCounterIncStmt() {
        return core_1.types.expressionStatement(makeCounterIncExpr());
    }
    function makeCounterIncExpr() {
        return core_1.types.callExpression
        (core_1.types.identifier("Fuzzer.coverageTracker.incrementCounter"), 
            [core_1.types.numericLiteral(idStrategy.nextEdgeId())]);
    }
    return () => {
        return {
            visitor: {
                // eslint-disable-next-line @typescript-eslint/ban-types
                Function(path) {
                    if ((0, types_1.isBlockStatement)(path.node.body)) {
                        const bodyStmt = path.node.body;
                        if (bodyStmt) {
                            bodyStmt.body.unshift(makeCounterIncStmt());
                        }
                    }
                },
                IfStatement(path) {
                    path.node.consequent = addCounterToStmt(path.node.consequent);
                    if (path.node.alternate) {
                        path.node.alternate = addCounterToStmt(path.node.alternate);
                    }
                    path.insertAfter(makeCounterIncStmt());
                },
                SwitchStatement(path) {
                    path.node.cases.forEach((caseStmt) => caseStmt.consequent.unshift(makeCounterIncStmt()));
                    path.insertAfter(makeCounterIncStmt());
                },
                Loop(path) {
                    path.node.body = addCounterToStmt(path.node.body);
                    path.insertAfter(makeCounterIncStmt());
                },
                TryStatement(path) {
                    const catchStmt = path.node.handler;
                    if (catchStmt) {
                        catchStmt.body.body.unshift(makeCounterIncStmt());
                    }
                    path.insertAfter(makeCounterIncStmt());
                },
                LogicalExpression(path) {
                    if (!(0, types_1.isLogicalExpression)(path.node.left)) {
                        path.node.left = core_1.types.sequenceExpression([
                            makeCounterIncExpr(),
                            path.node.left,
                        ]);
                    }
                    if (!(0, types_1.isLogicalExpression)(path.node.right)) {
                        path.node.right = core_1.types.sequenceExpression([
                            makeCounterIncExpr(),
                            path.node.right,
                        ]);
                    }
                },
                ConditionalExpression(path) {
                    path.node.consequent = core_1.types.sequenceExpression([
                        makeCounterIncExpr(),
                        path.node.consequent,
                    ]);
                    path.node.alternate = core_1.types.sequenceExpression([
                        makeCounterIncExpr(),
                        path.node.alternate,
                    ]);
                    if ((0, types_1.isBlockStatement)(path.parent)) {
                        path.insertAfter(makeCounterIncStmt());
                    }
                },
            },
        };
    };
}
exports.codeCoverage = codeCoverage;
//# sourceMappingURL=codeCoverage.js.map