"""Exercise the shell dependency gate without requiring cross compilers."""
from pathlib import Path
import subprocess
import sys

DRIVER = Path(__file__).resolve().parents[2] / 'experiment/acquire_real_project_builds.sh'


def test_source_failure_stops_before_capture_and_build(tmp_path):
    tooling=tmp_path/'tooling'; scripts=tooling/'experiment'; scripts.mkdir(parents=True)
    (scripts/'check_project_acquisition.py').write_text('print("available")\n')
    (scripts/'prepare_real_project_experiment.py').write_text('import sys;print("source-check-failed");sys.exit(9)\n')
    (scripts/'capture_project_build.py').write_text('raise RuntimeError("must not execute")\n')
    prep=tmp_path/'prep';prep.mkdir();archives=tmp_path/'archives';archives.mkdir()
    output=tmp_path/'new-result'
    run=subprocess.run(['bash',str(DRIVER),str(tooling),str(prep),str(archives),str(output),'gmp'],capture_output=True,text=True)
    assert run.returncode==9
    assert 'status=9' in run.stderr
    assert 'source-check-failed' in (output/'source.log').read_text()
    assert not (output/'capture').exists() and not (output/'build').exists()
    retry=subprocess.run(['bash',str(DRIVER),str(tooling),str(prep),str(archives),str(output),'gmp'],capture_output=True)
    assert retry.returncode!=0
