#!/usr/bin/env python3
"""Build the standalone Linux x86-64 JNI command bridge into a fresh directory."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent
REVISION = '98c61149d1e2ca769f7d27f96960c42633548903'

def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

def run(command, output, label):
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=False)
    (output / (label + '.stdout')).write_bytes(result.stdout)
    (output / (label + '.stderr')).write_bytes(result.stderr)
    if result.returncode:
        raise RuntimeError(f'{label} exited {result.returncode}; see {output / (label + ".stderr")}')
    return {'command': command, 'returncode': result.returncode}

def main():
    """Copy source inputs, derive a bridge identity, compile and record both artifact hashes."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--jdk', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--cc', default='cc')
    args = parser.parse_args()
    jdk = args.jdk.resolve(strict=True)
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=False)
    src = out / 'source'
    java_name = 'java/org/elasticsearch/painless/OwnedNativeCommand.java'
    native_sources = ['native_command.c', 'elf_loader.c', 'process_supervisor.c', 'command_internal.h']
    source_names = [*native_sources, java_name, 'third-party/libreflect-COPYING', 'build.py']
    for name in source_names:
        dest = src / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, dest)
    template = (src/java_name).read_bytes()
    if template.count(b'__BRIDGE_BUILD_ID__') != 1:
        raise RuntimeError('Expected exactly one bridge build-ID placeholder')
    build_id = hashlib.sha256(b'java4shell-native-command-v2\0'+template+b'\0'+b'\0'.join((src/name).read_bytes() for name in native_sources)).hexdigest()
    generated = out/'generated'/java_name
    generated.parent.mkdir(parents=True, exist_ok=True)
    generated.write_bytes(template.replace(b'__BRIDGE_BUILD_ID__', build_id.encode('ascii')))
    cc = shutil.which(args.cc)
    if not cc:
        raise RuntimeError(f'Compiler unavailable: {args.cc}')
    javac = jdk / 'bin/javac'
    lib = out / 'libowned-native-command.so'
    classes = out / 'classes'
    classes.mkdir()
    c_command = [cc, '-std=gnu11', '-O2', '-g0', '-Wall', '-Wextra', '-Werror', '-fPIC', '-shared',
                 '-Wl,-z,now', '-I'+str(jdk/'include'), '-I'+str(jdk/'include/linux'),
                 *[str(src/name) for name in native_sources if name.endswith('.c')], '-o', str(lib)]
    java_command = [str(javac), '--release', '17', '-d', str(classes), str(generated)]
    cc_version = subprocess.run([cc, '--version'], capture_output=True, text=True, check=True).stdout
    javac_version = subprocess.run([str(javac), '-version'], capture_output=True, text=True, check=True)
    c_result = run(c_command, out, 'cc')
    java_result = run(java_command, out, 'javac')
    bridge = classes / 'org/elasticsearch/painless/OwnedNativeCommand.class'
    manifest = {
        'schema_version': 1,
        'platform': 'linux-x86_64',
        'api': 'org.elasticsearch.painless.OwnedNativeCommand.run(SeekableByteChannel, String[], int) -> byte[][]',
        'creation_api': 'org.elasticsearch.painless.OwnedNativeCommand.openAnonymous(String) -> SeekableByteChannel',
        'library_storage': 'Linux O_TMPFILE|O_EXCL; caller-owned descriptor; no named-path fallback',
        'bridge_build_id': build_id,
        'bridge_class': bridge.relative_to(out).as_posix(),
        'bridge_class_sha256': sha256(bridge),
        'native_library': lib.relative_to(out).as_posix(),
        'native_library_sha256': sha256(lib),
        'sources': [{'path': (Path('source')/name).as_posix(), 'sha256': sha256(src/name)} for name in source_names],
        'generated_sources': [{'path': generated.relative_to(out).as_posix(), 'sha256': sha256(generated)}],
        'compiler': {'version': cc_version.strip(), **c_result},
        'javac': {'version': (javac_version.stdout+javac_version.stderr).strip(), **java_result},
        'linked_dependencies': [],
        'design_provenance': [{
            'repository': 'https://github.com/rapid7/mettle',
            'revision': REVISION,
            'source': f'https://github.com/rapid7/mettle/blob/{REVISION}/libreflect/arch/linux/x86_64/arch_jump.h',
            'use': 'Three-instruction x86-64 stack/entry handoff adapted; mapper, stack construction and process handling are self-authored.',
            'license': 'BSD-3-Clause',
            'notice': 'source/third-party/libreflect-COPYING',
        }, {
            'repository': 'https://github.com/elastic/elasticsearch',
            'revision': '580aff1a0064ce4c93293aaab6fcc55e22c10d1c',
            'use': 'Test-only exact amd64 seccomp blacklist; never installed by application run().',
        }],
    }
    (out/'build.json').write_text(json.dumps(manifest, indent=2)+'\n')
    print(json.dumps({k: manifest[k] for k in ('bridge_build_id','bridge_class','bridge_class_sha256','native_library','native_library_sha256')}, indent=2))

if __name__ == '__main__':
    main()
