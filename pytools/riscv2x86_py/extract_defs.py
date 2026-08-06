import ast
import sys
from typing import Set, List, Dict


class TargetExtractor(ast.NodeVisitor):
    def __init__(self, target_names: Set[str]):
        self.target_names = target_names
        self.results: List[Dict] = []

    def visit_ClassDef(self, node: ast.ClassDef):
        if node.name in self.target_names:
            self.results.append({
                "type": "class",
                "name": node.name,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
            })
        self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        if node.name in self.target_names:
            self.results.append({
                "type": "function",
                "name": node.name,
                "start_line": node.lineno,
                "end_line": node.end_lineno,
            })
        self.generic_visit(node)


def extract_source_from_file(filepath: str, target_names: Set[str]) -> List[dict]:
    with open(filepath, "r", encoding="utf-8") as f:
        lines = f.readlines()
    try:
        tree = ast.parse("".join(lines), filename=filepath)
    except SyntaxError as e:
        print(f"[ERROR] 文件语法错误 {filepath}: {e}", file=sys.stderr)
        return []

    visitor = TargetExtractor(target_names)
    visitor.visit(tree)
    output = []
    for item in visitor.results:
        s = item["start_line"] - 1
        e = item["end_line"]
        code_snippet = "".join(lines[s:e])
        output.append({
            "file": filepath,
            "type": item["type"],
            "name": item["name"],
            "start_line": item["start_line"],
            "end_line": item["end_line"],
            "code": code_snippet
        })
    return output


def main():
    args = sys.argv[1:]
    if len(args) < 2 or not args[0].startswith("--names="):
        print("用法：")
        print('python3 extract_defs.py --names="func1,ClassNameA,func2"  fileA.py fileB.py')
        sys.exit(1)

    name_part = args[0].removeprefix("--names=")
    all_targets = set(n.strip() for n in name_part.split(",") if n.strip())
    file_list = args[1:]

    found_names = set()

    for pyfile in file_list:
        items = extract_source_from_file(pyfile, all_targets)
        for it in items:
            found_names.add(it["name"])
            print("=" * 80)
            print(f"【{it['file']}】 {it['type']} {it['name']} 行范围:{it['start_line']} ~ {it['end_line']}")
            print("=" * 80)
            print(it["code"])

    # 汇总未找到的名称
    missing = sorted(all_targets - found_names)
    if missing:
        print("\n" + "!" * 80, file=sys.stderr)
        print(f"警告：以下 {len(missing)} 个类/函数 在所有目标文件中未检索到：", file=sys.stderr)
        for name in missing:
            print(f" - {name}", file=sys.stderr)
        print("!" * 80, file=sys.stderr)


if __name__ == "__main__":
    main()