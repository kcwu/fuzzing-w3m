#!/usr/bin/env python3
#
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
import argparse
import logging
import os
import re
import resource
import signal
import subprocess
import textwrap
import time
import hashlib

import yaml

logging.basicConfig(
        level=logging.DEBUG,
        format='\x1b[1;33m%(asctime)s %(levelname)s %(message)s\x1b[m')
logger = logging.getLogger()

case_dir = 'cases'

all_targets = [
        ('./w3m-tats', 'tats master'),
        ('./w3m-tats.20160718', 'tats v0.5.3+git20160718'),
        ('./w3m-0.5.3', 'origin 0.5.3'),
        ('./w3m-0.5.3+debian-15', 'debian 0.5.3-15'),
        ('./freebsd-w3m-0.5.3_6', 'freebsd 0.5.3_6'),
]

#if os.path.exists('/usr/bin/w3m'):
#    all_targets.append(('/usr/bin/w3m', 'system w3m'))
#elif os.path.exists('/usr/local/bin/w3m'):
#    all_targets.append(('/usr/local/bin/w3m', 'system w3m'))

all_detectors = [
        'none',
        'asan',
        '+m',
        '+m+d',
        'asan+m',
        'msan',
        'ubsan',
        'valgrind',
        'valgrind+m',
        ]

parser = argparse.ArgumentParser()
parser.add_argument('--target', default='all', metavar='EXE',
        help='target (w3m executable) to run. [default=all]')
parser.add_argument('--detector', default='all',
        help='detectors to run, sample values are %s [default=all]' % ','.join(all_detectors))
parser.add_argument('--bug', action='store_true',
        help='produce bug report template')
parser.add_argument('--nocache', action='store_true')
parser.add_argument('cases', nargs='*')

args = parser.parse_args()


def cache(func):
    h = {}
    def wrapper(fn):
        if fn in h:
            return h[fn]
        h[fn] = func(fn)
        return h[fn]
    return wrapper

@cache
def file_md5(fn):
    return hashlib.md5(open(fn, 'rb').read()).hexdigest()

def setlimits(m):
    if m > 10000:
        return
    m *= 2**20
    resource.setrlimit(resource.RLIMIT_AS, (m, m))
    resource.setrlimit(resource.RLIMIT_DATA, (m, m))
    resource.setrlimit(resource.RLIMIT_STACK, (m, m))
    resource.setrlimit(resource.RLIMIT_RSS, (m, m))

def run(target, detector, fn):
    env = {}
    mem_limit = 200
    time_limit = 1.0
    prefix = []
    result = dict(target=target, detector=detector, filename=fn, file_md5=file_md5(fn))

    # special suffix
    while True:
        if detector.endswith('+m'):
            detector = detector[:-2]
            env['LD_LIBRARY_PATH'] = './notgc'
            time_limit *= 3
            continue
        if detector.endswith('+d'):
            detector = detector[:-2]
            env['LD_PRELOAD'] = './AFLplusplus/utils/libdislocator/libdislocator.so'
            mem_limit = 1e100
            continue
        break

    if detector == 'none' or detector == '':
        exe = target
    elif detector == 'asan':
        exe = target + '.' + detector
        env['ASAN_OPTIONS'] = 'abort_on_error=1:detect_leaks=0'
        mem_limit = 1e100
    elif detector == 'msan':
        exe = target + '.' + detector
        env['MSAN_OPTIONS'] = 'abort_on_error=1'
        mem_limit = 1e100
    elif detector == 'ubsan':
        exe = target + '.' + detector
        env['UBSAN_OPTIONS'] = 'halt_on_error=1:abort_on_error=1:print_stacktrace=1'
    elif detector == 'valgrind':
        exe = target
        env['GC_DONT_GC'] = '1'
        prefix = ['valgrind', '--leak-check=no', '-q', '--error-exitcode=99']
        time_limit *= 10
        mem_limit *= 2
    else:
        assert 0, 'unknown detecot: ' + repr(detector)

    result['exe'] = exe
    if not os.path.exists(exe):
        result['status'] = 'n/a'
        return result
    result['exe_md5'] = file_md5(exe)

    cmd = prefix + [exe, '-T', 'text/html', '-dump', fn]
    result['cmd'] = cmd
    result['env'] = env.copy()
    cmdline = []
    for k, v in env.items():
        cmdline.append('%s=%s' % (k, v))
    cmdline.append(subprocess.list2cmdline(cmd))
    logger.debug('command line: %s', ' '.join(cmdline))
    env.update(os.environ)

    p = subprocess.Popen(cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            preexec_fn=lambda: setlimits(mem_limit))

    t0 = time.time()
    try:
        def kill_child(*a):
            try:
                p.kill()
            except OSError:
                pass
        signal.signal(signal.SIGALRM, kill_child)
        signal.setitimer(signal.ITIMER_REAL, time_limit)
        stdout, stderr = p.communicate()
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, signal.SIG_DFL)
    t1 = time.time()
    if t1 - t0 >= time_limit:
        result.update(status='timeout')
        return result

    stderr = stderr.decode('utf8')
    stderr = stderr.replace(os.path.realpath('.'), '')
    result.update(status='return', stderr=stderr, returncode=p.returncode)
    return result

def case_sort_key(case):
    keys = re.split('(\d+)', case)
    keys = [ int(k) if k.isdigit() else k for k in keys ]
    return keys

def linkify(text):
    if isinstance(text, list):
        return '<br>'.join(map(linkify, text))
    if re.match('^CVE-\d+-\d+$', text):
        return '<a href=http://cve.mitre.org/cgi-bin/cvename.cgi?name=%s>%s</a>' % (text, text)
    if re.match('^http', text):
        return '<a href=%s>%s</a>' % (text, 'link')
    return text

def get_cache_fn(target, detector, case_path):
    cache_dir = os.path.join('cache', target.replace('/', '_').lstrip('.'), detector)
    if not os.path.exists(cache_dir):
        os.makedirs(cache_dir)
    head, tail = os.path.split(case_path)
    if head == case_dir:
        fn = tail
    else:
        fn = file_md5(case_path)
    return os.path.join(cache_dir, fn)

def reproduce(target, detector, case_path):
    cache_fn = get_cache_fn(target, detector, case_path)
    result = None
    if not args.nocache and os.path.exists(cache_fn):
        cache = yaml.safe_load(open(cache_fn))
        if cache.get('exe'):
            if not os.path.exists(cache['exe']):
                # foreign result
                result = cache
            elif file_md5(cache['exe']) == cache.get('exe_md5') and file_md5(case_path) == cache.get('file_md5'):
                result = cache
    if not result:
        result = run(target, detector, case_path)
        assert result
        with open(cache_fn, 'w') as f:
            yaml.dump(result, f)

    stderr = result.get('stderr', '')
    status = result['status']
    if status == 'return':
        prefix = ''
        if 'heap-buffer-overflow' in stderr:
            prefix = 'heap '
        elif 'stack-buffer-overflow' in stderr:
            prefix = 'stack '
        elif 'global-buffer-overflow' in stderr:
            prefix = 'glboal '
        elif 'use-after-free' in stderr:
            prefix = 'UAF '

        m = re.search(r'Process terminating with default action of signal (\d+)', stderr)
        if m:
            status = -int(m.group(1))
        elif 'AddressSanitizer: SEGV' in stderr:
            status = -signal.SIGSEGV
        elif 'stack-overflow' in stderr:
            status = 'SO'
        elif 'Invalid write of size' in stderr or 'WRITE of size' in stderr:
            status = prefix + 'write'
        elif 'Invalid read of size' in stderr or 'READ of size' in stderr:
            status = prefix + 'read'
        elif 'Conditional jump or move depends on uninitialised value' in stderr or 'use-of-uninitialized-value' in stderr:
            status = 'uninit'
        elif 'variable length array bound evaluates to non-positive value 0' in stderr:
            status = '[0]'
    if status == 'return':
        status = result['returncode']
    logger.info('[%s] %s %s: %s', case_path, target, detector, status)
    if status != 0:
        if ("*** [AFL] mprotect() failed when allocating memory ***" in stderr or
                "Out of memory: " in stderr):
            status = 'OOM'
        if args.bug:
            assert os.path.exists(result['filename'])
            print(textwrap.dedent('''
            input (`xxd {}`)
            ```
            {}
            ```
            ''').format(
                    result['filename'],
                    subprocess.check_output(['xxd', result['filename']], encoding='utf8').strip()).lstrip())

            cmdline = subprocess.list2cmdline(result['cmd'])
            for k, v in result['env'].items():
                cmdline = '%s=%s ' % (k, v) + cmdline

            print(textwrap.dedent('''
            how to reproduce:
            ```
            {}
            ```
            ''').format(cmdline).lstrip())

            if stderr:
                print(textwrap.dedent('''
                stderr:
                ```
                {}
                ```
                ''').format(stderr.strip()).lstrip())

            if '+m' in detector:
                print('This is detected with help of dummy libgc wrapper. See https://github.com/kcwu/fuzzing-w3m/tree/master/notgc for detail.')
            if '+d' in detector:
              print('This is detected with help of libdislocator, an abusive allocator. See https://github.com/AFLplusplus/AFLplusplus/tree/stable/utils/libdislocator for detail.')
            print('More detail to reproduce please see https://github.com/kcwu/fuzzing-w3m')

            if 'valgrind' not in cmdline:
                print()
                print('For your convenience,')
                gdbcmd = ['gdb']
                gdbenv = []
                for k, v in result['env'].items():
                    if k == 'LD_PRELOAD':
                        gdbcmd += ['-ex', 'set environment %s=%s' % (k, v)]
                    else:
                        gdbenv.append('%s=%s' % (k, v))
                gdbcmd += ['--args'] + result['cmd']
                gdbline = ' '.join(gdbenv + [subprocess.list2cmdline(gdbcmd)])
                print('gdbline:')
                print(gdbline)

        else:
            print(stderr.rstrip())

    print

    return status

def aslist(x):
    if x is None:
        return []
    if isinstance(x, list):
        return x
    return [x]

def main():

    if args.detector == 'all':
        detectors = all_detectors
    else:
        detectors = args.detector.split(',')

    if args.cases:
        cases = args.cases
    else:
        cases = sorted(os.listdir(case_dir), key=case_sort_key)

    if args.target == 'all':
        targets = all_targets
    else:
        targets = [(args.target, '')]

    known_cases = {}
    with open('cases.yaml') as f:
      entries = yaml.safe_load(f)
    groups = []
    for i, entry in enumerate(entries):
        found = []
        entry['bug'] = aslist(entry.get('bug'))
        entry['case'] = aslist(entry.get('case'))
        for case in entry['case']:
            if case in cases:
                found.append(case)
                known_cases[case] = len(groups)
            bug = None
            m = re.match(r'^tats-w3m-(\d+)', case)
            if m:
                bug = 'https://github.com/tats/w3m/issues/%s' % m.group(1)
            m = re.match(r'^debian-(\d+)', case)
            if m:
                bug = 'https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=%s' % m.group(1)
            if bug and bug not in entry['bug']:
                entry['bug'].append(bug)
        if found:
            entry['case'] = found
            groups.append(entry)
    for case in cases:
        if case in known_cases:
            continue
        if os.path.exists(case):
            groups.append(dict(case=[case]))
        else:
            logging.error('file not found: %s', case)


    with open('report.html', 'w') as report:
        report.write('<table border=1>')
        report.write('<tr>')
        report.write('<td></td>')
        report.write('<td></td>')
        report.write('<td></td>')
        for target, desc in targets:
            report.write('<th colspan=%d>%s<br>(%s)</th>' % (len(detectors), desc, target))
        report.write('</tr>')

        report.write('<tr>')
        report.write('<th>case</th>')
        report.write('<th>bug</th>')
        report.write('<th>cve</th>')
        for _ in targets:
            for detector in detectors:
                report.write('<td>%s</td>' % (detector))
        report.write('</tr>')

        for group in groups:
            for gi, case in enumerate(group['case']):
                if os.path.exists(case):
                    path = case
                else:
                    path = os.path.join(case_dir, case)

                report.write('<tr><td>%s</td>' % case)
                if case in known_cases:
                    report.write('<td>%s</td>' % linkify(group.get('bug', '')))
                    if gi == 0:
                        report.write('<td rowspan=%d>%s</td>' % (
                            len(aslist(group['case'])),
                            linkify(group.get('cve', ''))))
                else:
                    report.write('<td></td>')
                    report.write('<td></td>')
                for target, desc in targets:
                    for detector in detectors:
                        status = reproduce(target, detector, path)
                        if status == 0:
                            bg = '#80ff80'
                        elif status == 'TL':
                            bg = '#ffff80'
                        elif status == 'n/a':
                            bg = 'white'
                        elif isinstance(status, int) and status < 0:
                            bg = '#ff8080'
                        else:
                            bg = '#ff80ff'
                        result = {
                                -signal.SIGSEGV: 'segv',
                                -signal.SIGABRT: 'abrt',
                                'timeout': 'TL',
                                99: 'err',
                                }.get(status, status)
                        report.write('<td style="background: %s;">%s</td>' % (bg, result))
                report.write('</tr>')
        report.write('</table>')
        report.write("This table is generated by an automatical script without human analysis. Many false positives and false negatives due to limitation of my script.<p>")
        report.write('Detector: +m: use libgc wrapper, +d: use libdislocator<p>')
        report.write('''Table value:<ul>
        <li>err: valgrind detected errors.
        <li>TL: time limit exceeded.
        <li>OOM: maybe OOM, infinite recursion, or allocate buffer of negative size. However, libdislocator(+d) may require too much memory (in this case, it's false alarm).
        </ul>''')


if __name__:
    main()
