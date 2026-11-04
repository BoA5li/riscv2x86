"""Resolve a tool using the working directory of the action, including PATH."""
import os
from pathlib import Path
import shutil


def resolve_executable(name,cwd=None):
    if not isinstance(name,str) or not name:raise ValueError('PROJECT_EXECUTABLE_NAME_REQUIRED')
    cwd=Path(cwd or Path.cwd()).resolve(strict=True)
    p=Path(name)
    if p.is_absolute():selected=p
    elif '/' in name:selected=cwd/p
    else:
        search=os.environ.get('PATH',os.defpath)
        paths=[str(Path(x) if Path(x).is_absolute() else cwd/x) for x in search.split(os.pathsep)]
        found=shutil.which(name,path=os.pathsep.join(paths))
        if found is None:raise FileNotFoundError('PROJECT_EXECUTABLE_NOT_FOUND:'+name)
        selected=Path(found)
    selected=selected.resolve(strict=True)
    if not selected.is_file() or not os.access(selected,os.X_OK):
        raise ValueError('PROJECT_EXECUTABLE_FILE_REQUIRED:'+str(selected))
    return selected
