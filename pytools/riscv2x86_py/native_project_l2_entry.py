"""Captured-project execution backend for the ORIGINAL L2 operand validator.

Only builds approved observation variants. No translation, proof synthesis,
compiler-option substitution, guessed pointer bounds or alternate comparator.
Readback regenerates commands/materialization and consumes retained executions.
"""
from pathlib import Path
import subprocess
from . import native_captured_deployment as d
from . import native_original_api as api
from . import native_project_evaluation as project
from . import l2_typed_entry as entry


class ProjectEntry:
    def __init__(self, config, *, readback=False):
        self.config = config; self.readback = readback
        cfg = config['typedProjectEntry']
        required = {'specPath', 'requestPath', 'sourceBuild', 'targetBuild'}
        if set(cfg) not in (required, required | {'applicabilityPath'}):
            raise ValueError('L2_TYPED_PROJECT_CONFIG_INVALID')
        self.refs = [d.snapshot(cfg[k]) for k in cfg]
        self.spec, self.request, self.selected, _, _ = api.request_context(cfg['specPath'], cfg['requestPath'])
        self.builds = api.current_builds(self.spec, {'builds': {
            side: d.snapshot(cfg[side + 'Build']) for side in api.SIDES}})
        run = d.read(self.spec['run']['path']); translation = d.read(run['translation']['path'])
        self.refs.extend((self.spec['run'], run['translation'], translation['report']))
        if d.digest(config['translatedReport']) != translation['report']['digest']:
            raise ValueError('L2_TYPED_ORIGINAL_REPORT_MISMATCH')
        report = d.read(config['translatedReport'])
        if config['functions'] != report['functions']:
            raise ValueError('L2_TYPED_ORIGINAL_FUNCTIONS_MISMATCH')
        for side in api.SIDES:
            if (d.digest(config[side + 'Path']) != self.builds[side]['input']['digest']
                    or config[side + 'Digest'] != self.builds[side]['input']['digest']):
                raise ValueError('L2_TYPED_ORIGINAL_BODY_MISMATCH')
        if config['qemuBinary'] != self.spec['qemu']['path'] or config['timeoutSeconds'] != self.spec['timeoutSeconds']:
            raise ValueError('L2_TYPED_RUNNER_CONTEXT_MISMATCH')
        self.profile = None; self.comparison = None
        self.verify()

    def verify(self):
        for row in self.refs: d.verify_snapshot(row)
        for row in self.builds.values():
            for key in ('input', 'object', 'library', 'program'): d.verify_snapshot(row[key])
        for p in self.spec['profiles'].values():
            d.verify_snapshot(p['compile']['compiler'])
            d.verify_snapshot(p['entry']['compiler'])
            for row in p['entry']['inputs']:
                d.verify_snapshot({k: row[k] for k in ('path', 'resolvedPath', 'digest')})
        d.verify_snapshot(self.spec['qemu'])

    def bind(self, function):
        self.profile = entry.bind(function, self.selected, self.request['domain'])
        return self.profile

    def instance_disposition(self, finding):
        """Recheck the bound receipt, rather than trusting an invocation flag."""
        cfg = self.config['typedProjectEntry']
        if 'applicabilityPath' not in cfg:
            return None  # legacy configurations retain their original admission
        from .native_original_applicability import check
        from .native_instance_execution import classify
        self.verify()
        app = check(cfg['applicabilityPath'])
        value = classify(finding, self.selected, app, d.snapshot(cfg['specPath']))
        self.verify()
        return value

    def execute(self, harness, source, target, work, wrapper):
        self.verify(); results = {}; rows = {}; streams = {}
        work = Path(work)
        for side, body in (('source', source), ('target', target)):
            p = self.spec['profiles'][side]; compile = p['compile']; build = self.builds[side]
            obj = work / (side + '-observed.o'); driver = work / (side + '-entry.o')
            executable = work / (side + '-observed'); mapfile = work / (side + '-observed.map')
            old_main = api.entry_object(p)
            replacements = {i: Path(build['library']['path']) for i in p['entryLibraryPositions']}
            replacements[old_main['argumentIndex']] = driver
            link = d._argv(p['entry'], executable, replacements, str(Path(build['library']['path']).parent))
            link.insert(1, str(obj)); link += ['-Xlinker', '-Map', '-Xlinker', str(mapfile),
                                             '-Xlinker', '--trace-symbol', '-Xlinker', self.selected['name']]
            commands = [
                ('body-' + side, [compile['compiler']['path'], *compile['flags'], '-c', str(body), '-o', str(obj)],
                 compile['directory'], compile['environment']),
                ('driver-' + side, [compile['compiler']['path'], *compile['flags'], '-x', 'c', '-std=gnu11',
                 '-Werror', '-c', str(harness), '-o', str(driver)], compile['directory'], compile['environment']),
                ('link-' + side, link, p['entry']['directory'], p['environment'])]
            prefix = [self.spec['qemu']['path'], '-L', self.spec['runtimePrefix']] if side == 'source' else []
            commands.append(('run-' + side, [*prefix, str(executable)], str(work), p['environment']))
            variant_refs = [d.snapshot(body), d.snapshot(harness)]
            for name, argv, cwd, env in commands:
                folder = work / name
                if not self.readback:
                    project.command(argv, cwd, env, folder, self.spec['timeoutSeconds'])
                row = project.validate_execution_record(d.read(folder / 'execution.json'))
                if any(row[k] != v for k, v in {'arguments': argv, 'directory': cwd, 'environment': env}.items()):
                    raise ValueError('L2_TYPED_EXECUTION_RECIPE_CHANGED')
                if not name.startswith('run-') and (row['returnCode'] != 0 or row['failureReason']):
                    raise ValueError('L2_TYPED_PROJECT_BUILD_UNAVAILABLE:' + name)
                for ref in variant_refs: d.verify_snapshot(ref)
                self.verify()
            if d.definitions(d.parse(obj.read_bytes())) != d.definitions(d.parse(Path(build['object']['path']).read_bytes())):
                raise ValueError('L2_TYPED_OBSERVER_CHANGED_DEFINITION_INTERFACE')
            attribution = d.attribution(obj, executable, mapfile)
            selected = [r for r in attribution['definitions'] if r['symbol']['name'] == self.selected['name']]
            if len(selected) != 1 or not selected[0]['verified']:
                raise ValueError('L2_TYPED_OBSERVER_BODY_LINK_UNBOUND')
            stdout = (work / ('run-' + side) / 'stdout.log').read_bytes()
            stderr = (work / ('run-' + side) / 'stderr.log').read_bytes()
            lines = stdout.splitlines(keepends=True)
            if any(not line.startswith((b'case:', b'operand_trace=', b'internal_trace', b'dependency_trace;')) for line in lines):
                raise ValueError('L2_TYPED_UNKNOWN_OBSERVER_OUTPUT')
            streams[side] = (b''.join(line for line in lines if line.startswith(b'case:')), stderr)
            rows['run-' + side] = row
            results[side] = subprocess.CompletedProcess((), row['returnCode'], stdout.decode('utf-8'), stderr.decode('utf-8'))
            if row['failureReason']:
                raise ValueError('L2_TYPED_PROJECT_EXECUTION_UNAVAILABLE:' + row['failureReason'])
        self.comparison = api.compare_outputs(rows, streams, self.selected, self.request['domain'])
        self.verify()
        return results['source'], results['target']
