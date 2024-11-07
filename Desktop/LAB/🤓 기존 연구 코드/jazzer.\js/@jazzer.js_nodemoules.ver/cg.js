const parser = require('@babel/parser');
const traverse = require('@babel/traverse').default;
const fs = require('fs');
const pathModule = require('path');

// 함수 정의를 저장할 전역 객체
const functionDefinitions = {};

// 호출 관계를 저장할 집합
const callRelations = new Set();

// 이미 분석한 파일을 추적하기 위한 집합
const analyzedFiles = new Set();

// 분석 대상 폴더 경로를 저장
let targetDirectory = '';

// 지정된 경로를 분석하는 함수 (파일 또는 디렉토리)
function analyzePath(targetPath) {
    if (!fs.existsSync(targetPath)) {
        console.error(`지정된 경로가 존재하지 않습니다: ${targetPath}`);
        return;
    }

    const stat = fs.statSync(targetPath);

    if (stat.isDirectory()) {
        // 디렉토리인 경우, 내부의 모든 파일과 디렉토리를 재귀적으로 탐색합니다.
        const entries = fs.readdirSync(targetPath);
        entries.forEach((entry) => {
            const entryPath = pathModule.join(targetPath, entry);
            analyzePath(entryPath);
        });
    } else if (stat.isFile() && targetPath.endsWith('.js')) {
        // 파일인 경우, JS 파일이면 분석합니다.
        analyzeFile(targetPath);
    }
}

// 지정된 파일을 분석하는 함수
function analyzeFile(filePath) {
    // 이미 분석한 파일이면 건너뜁니다.
    if (analyzedFiles.has(filePath)) {
        return;
    }

    // 파일 여부 확인
    if (!fs.existsSync(filePath)) {
        console.error(`파일이 존재하지 않습니다: ${filePath}`);
        return;
    }
    const stat = fs.statSync(filePath);
    if (!stat.isFile()) {
        // 파일이 아니면 처리하지 않습니다.
        return;
    }

    analyzedFiles.add(filePath);

    const code = fs.readFileSync(filePath, 'utf8');

    let ast;
    try {
        ast = parser.parse(code, {
            sourceType: 'module', // ES 모듈로 파싱
            plugins: ['jsx', 'typescript', 'classProperties', 'dynamicImport'],
            locations: true,
        });
    } catch (error) {
        console.error(`파싱 오류: ${filePath}\n${error}`);
        return;
    }

    // 함수 정의 수집
    traverse(ast, {
        enter(path) {
            if (
                path.isFunctionDeclaration() ||
                path.isFunctionExpression() ||
                path.isArrowFunctionExpression() ||
                path.isClassMethod() ||
                path.isObjectMethod()
            ) {
                collectFunctionDefinition(path, filePath);
            }
        },
    });

    // 함수 호출 추적 및 모듈 의존성 처리
    traverse(ast, {
        enter(path) {
            if (path.isCallExpression()) {
                collectFunctionCall(path, filePath);
            }

            // 모듈 의존성 추적 (import, require)
            if (path.isImportDeclaration()) {
                const requiredModule = path.node.source.value;
                const requiredPath = resolveModulePath(filePath, requiredModule);
                if (requiredPath && fs.existsSync(requiredPath)) {
                    analyzeFile(requiredPath);
                }
            } else if (
                path.isCallExpression() &&
                path.node.callee.type === 'Identifier' &&
                path.node.callee.name === 'require' &&
                path.node.arguments.length === 1 &&
                path.node.arguments[0].type === 'StringLiteral'
            ) {
                const requiredModule = path.node.arguments[0].value;
                const requiredPath = resolveModulePath(filePath, requiredModule);
                if (requiredPath && fs.existsSync(requiredPath)) {
                    analyzeFile(requiredPath);
                }
            }
        },
    });
}

// 함수 정의 수집 함수
function collectFunctionDefinition(path, filePath) {
    const funcName = getFunctionName(path);
    if (!funcName) return; // 익명 함수는 건너뜁니다.

    // 동일한 함수 이름이 이미 존재하면 저장하지 않습니다.
    if (!functionDefinitions[funcName]) {
        functionDefinitions[funcName] = {
            name: funcName,
            loc: path.node.loc,
            file: filePath,
        };
    }
}

// 함수 호출 추적 함수
function collectFunctionCall(path, filePath) {
    const calleeName = getCalleeName(path.node.callee);
    if (!calleeName) return;

    const callerFunctionPath = path.getFunctionParent();
    let callerName = 'global';

    if (callerFunctionPath) {
        callerName = getFunctionName(callerFunctionPath) || 'anonymous';
    }

    const relation = `${callerName}->${calleeName}`;
    callRelations.add(relation);
}

// 함수 이름 추출 함수
function getFunctionName(path) {
    if (path.node.id && path.node.id.name) {
        return path.node.id.name;
    } else if ((path.isClassMethod() || path.isObjectMethod()) && path.node.key && path.node.key.name) {
        return path.node.key.name;
    } else if (path.parentPath.isVariableDeclarator() && path.parentPath.node.id.name) {
        return path.parentPath.node.id.name;
    } else if (path.parentPath.isAssignmentExpression() && path.parentPath.node.left.name) {
        return path.parentPath.node.left.name;
    } else {
        return null; // 익명 함수는 null 반환
    }
}

// callee 이름 추출 함수
function getCalleeName(callee) {
    if (callee.type === 'Identifier') {
        return callee.name;
    } else if (callee.type === 'MemberExpression') {
        const propertyName = callee.property.name || '';
        return propertyName; // 프로퍼티 이름만 사용
    } else {
        return null;
    }
}

// 모듈 경로를 해석하는 함수
function resolveModulePath(currentFile, modulePath) {
    const currentDir = pathModule.dirname(currentFile);

    if (modulePath.startsWith('.')) {
        // 로컬 모듈인 경우
        let resolvedPath = pathModule.resolve(currentDir, modulePath);
        if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isDirectory()) {
            resolvedPath = pathModule.join(resolvedPath, 'index.js');
        } else if (!pathModule.extname(resolvedPath)) {
            resolvedPath += '.js';
        }
        if (fs.existsSync(resolvedPath) && fs.statSync(resolvedPath).isFile()) {
            return resolvedPath;
        }
    } else {
        // 외부 모듈(node_modules 등)은 무시
        return null;
    }

    return null;
}

// 호출 그래프 출력 함수
function outputCallGraph() {
    console.log('digraph CallGraph {');
    console.log('    rankdir=LR;');

    // 노드 정의 (함수 정의에 기반)
    for (const funcName in functionDefinitions) {
        const func = functionDefinitions[funcName];
        const label = `${funcName}\\n${pathModule.basename(func.file)}`;
        console.log(`    "${funcName}" [label="${label}"];`);
    }

    // 호출 관계 정의
    for (const relation of callRelations) {
        const [callerName, calleeName] = relation.split('->');

        // callee가 함수 정의에 있는지 확인
        if (!functionDefinitions[calleeName]) {
            continue; // 함수 정의에 없는 경우 (내장 함수 등) 무시
        }

        console.log(`    "${callerName}" -> "${calleeName}";`);
    }

    console.log('}');
}

// 명령어 인자로부터 분석 대상 경로를 가져옵니다.
const targetPath = process.argv[2];

if (!targetPath) {
    console.error('분석할 파일이나 폴더의 경로를 입력해주세요.');
    console.error('사용법: node cg.js <분석대상경로>');
    process.exit(1);
}

const absoluteTargetPath = pathModule.resolve(process.cwd(), targetPath);

// 분석 대상 폴더 경로 설정
targetDirectory = absoluteTargetPath;

// 분석 시작
analyzePath(absoluteTargetPath);

// 호출 그래프 출력
outputCallGraph();
