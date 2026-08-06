
import ast
import sys
from pathlib import Path

def parse(filepath):
    p = Path(filepath)
    if not p.exists():
        print("文件不存在")
        return
    try:
        src = p.read_text(encoding="utf-8")
        tree = ast.parse(src)
    except Exception as e:
        print("解析失败:", e)
        return

    class_list = []
    func_list = []
    for parent in ast.walk(tree):
        for child in ast.iter_child_nodes(parent):
            if isinstance(child, ast.ClassDef):
                bases = [b.id for b in child.bases if isinstance(b, ast.Name)]
                class_list.append((child.name, child.lineno, bases))
            elif isinstance(child, ast.FunctionDef) and isinstance(parent, ast.Module):
                dec = [d.id for d in child.decorator_list if isinstance(d, ast.Name)]
                func_list.append((child.name, child.lineno, dec))

    print("======== Class ========")
    for name, line, base in class_list:
        print(f"行{line:3d}  class {name}  父类:{base}")
    print("\n======== Top Function ========")
    for name, line, dec in func_list:
        print(f"行{line:3d}  def {name}  装饰器:{dec}")

if __name__ == "__main__":
    parse(sys.argv[1])
