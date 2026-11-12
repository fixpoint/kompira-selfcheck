#!/usr/bin/env python3
"""Kompira Enterprise CA trust self-check (eMudhra / emSign incident, October 2026)

Checks whether the CA certificate lists used by Kompira still trust the root
certificates that were distrusted after the eMudhra / emSign incident.

This script is read-only. It does not change any setting. Without --online or
--host it makes no network connection at all.

Usage:
  Kompira 1.6 (on the Kompira server and on job manager servers, as root):
      /opt/kompira/bin/python -I kompira-ca-check.py [--online]
  Kompira 2.0 (in each kengine / kompira / jobmngrd container):
      docker exec -i <container> python -I - [--online] < kompira-ca-check.py
  Server certificate of Kompira only (e.g. on the Docker host of Kompira 2.0):
      python3 -I kompira-ca-check.py --certs-only --cert ssl/server.crt --host localhost

Options:
  --online        Also connect to the public test sites with requests and urllib
                  (needs Internet access; set https_proxy if a proxy is required:
                  http:// only, and the credentials in it are never printed)
  --cert FILE     Also check a server certificate file used by Kompira
                  (HTTPS / AMQPS)
  --host HOST[:PORT]
                  Also check the server certificate presented by HOST
                  (default port 443; use 5671 for AMQPS; write an IPv6
                  address as [ADDRESS]:PORT; no proxy is used)
  --certs-only    Check only the server certificates (--cert, --host and the
                  ones found in the Apache / RabbitMQ settings), not the CA lists
  --json          Print the results as JSON
  --no-color      Do not use colors

Exit status: 0 = OK (or only warnings), 1 = action required,
             2 = could not check everything (INCOMPLETE or UNKNOWN)
"""
import sys
sys.dont_write_bytecode = True    # leave no files behind (python -I ignores PYTHONDONTWRITEBYTECODE)

import argparse
import base64
import datetime
import email.utils
import glob
import hashlib
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import traceback

TOOL_VERSION = '1.0.0'

# SHA-256 fingerprints of the root certificates distrusted after the incident
DISTRUSTED_ROOTS = {
    'd7a7a0fb5d7e2731d771e9484ebcdef71d5f0c3e0a2948782bc83ee0ea699ef4':
        'AAA Certificate Services (Comodo AAA Services root)',
    '86a1ecba089c4a8d3bbe2734c612ba341d813e043cf9e8a862cd5c57a36bbe6b':
        'emSign ECC Root CA - G3',
}
# Test sites using a certificate issued by the leaked intermediate CA
# (https://emudhra.we-have-a-problem.com/)
TEST_SITES = ('dv-g3b-emudhra.we-have-a-problem.com',
              'dv-g3b-aaa-emudhra.we-have-a-problem.com')
EMUDHRA_MARKERS = (b'eMudhra', b'emSign')
ADVISORY = 'See the Kompira advisory on the eMudhra / emSign incident.'
FIXED_PIP = (26, 2, 2)
KOMPIRA16_PYTHON = '/opt/kompira/bin/python'
# OpenSSL looks up a CA directory (capath) only by hashed names
HASHED_NAME = re.compile(r'^[0-9a-f]{8}\.[0-9]+$')
# The Kompira 1.6 daemons (systemd units with an environment file each), and the variables that change their CA lists
DAEMONS = ('kompirad', 'kompira_jobmngrd', 'httpd')
CA_ENV_VARS = ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE', 'SSL_CERT_FILE', 'SSL_CERT_DIR')

OK, FAIL, WARN, INFO, SKIP = 'OK', 'FAIL', 'WARN', 'INFO', 'SKIP'
LABELS = {OK: '[ OK ]', FAIL: '[FAIL]', WARN: '[WARN]', INFO: '[INFO]', SKIP: '[SKIP]'}
COLORS = {OK: '32', FAIL: '1;31', WARN: '33', INFO: '0', SKIP: '33'}
NO_NETWORK_HINT = ' - no Internet access? If a proxy is required, set https_proxy.'

results = []
context = {'kompira2': False, 'kompira': False}
OLD_PYTHON = sys.version_info < (3, 7)
OLD_PYTHON_FIX = 'See the [WARN] line of Python.'      # the fixed certifi cannot be installed


def add(status, item, detail='', action='', requested=False):
    """Record a result. requested=True: a check the user asked for (a SKIP makes the result incomplete)."""
    results.append({'status': status, 'item': item, 'detail': detail, 'action': action,
                    'requested': requested})


# ---------------------------------------------------------------- utilities

def pem_blocks(path):
    """Return [(DER of the certificate, whether it is in OpenSSL's trusted format)] of a PEM file.

    OpenSSL's "TRUSTED CERTIFICATE" is a certificate followed by trust settings, which may
    trust or reject it. The settings are not interpreted here. OpenSSL also reads the old
    "X509 CERTIFICATE" header.
    """
    with open(path, 'rb') as f:
        data = f.read()
    blocks = []
    for kind, b64 in re.findall(rb'-----BEGIN (TRUSTED |X509 )?CERTIFICATE-----(.*?)'
                                rb'-----END (?:TRUSTED |X509 )?CERTIFICATE-----', data, re.S):
        trusted = kind == b'TRUSTED '
        try:
            der = base64.b64decode(b''.join(b64.split()))
        except ValueError:
            der = b''
        try:
            der = der[:der_item(der, 0)[2]]              # OpenSSL ignores what follows the certificate
        except (IndexError, ValueError):
            pass                                         # malformed: kept, so that it is not skipped silently
        blocks.append((der, trusted))
    return blocks


def pem_certs(path):
    """Return the DER bytes of the certificates in a PEM file."""
    return [der for der, _ in pem_blocks(path)]


def unloadable(path):
    """Why OpenSSL cannot load the CA file (e.g. a line lost while editing it), or None."""
    try:
        ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT).load_verify_locations(cafile=path)
    except OSError as e:                      # ssl.SSLError is an OSError
        return getattr(e, 'reason', None) or str(e)[:80] or type(e).__name__
    return None


def scan(paths):
    """Return ({path: distrusted roots found}, number of unique certificates,
    {path: distrusted roots found in OpenSSL's trusted format, whose trust settings are not read},
    {path: why it cannot be read}, {path: why OpenSSL cannot load it})."""
    hits, unclear, failed, broken, fingerprints, seen = {}, {}, {}, {}, set(), set()
    for path in paths:
        real = os.path.realpath(path)
        if real in seen:
            continue
        if os.path.isdir(real):               # from ca_files(): a CA directory that cannot be listed
            failed[path] = 'cannot list the directory'
            continue
        if not os.path.isfile(real):
            if denied(real):                  # e.g. in a directory that only root can enter
                failed[path] = 'PermissionError'
            continue
        seen.add(real)
        try:
            blocks = pem_blocks(real)
        except (OSError, IOError) as e:
            failed[path] = type(e).__name__
            continue
        why = unloadable(real)                # e.g. no certificate left: the HTTPS connections that use it fail
        if why:
            broken[path] = why
        for der, trusted in blocks:
            fp = hashlib.sha256(der).hexdigest()
            fingerprints.add(fp)
            if fp in DISTRUSTED_ROOTS:
                (unclear if trusted else hits).setdefault(path, set()).add(DISTRUSTED_ROOTS[fp])
    return hits, len(fingerprints), unclear, failed, broken


def denied(path):
    """Whether path cannot be looked up for lack of permission (root may still read it)."""
    try:
        os.stat(path)
    except PermissionError:
        return True
    except (OSError, ValueError):
        pass
    return False


def ca_files(path):
    """The files OpenSSL reads for a CA file, or for a CA directory (only the hashed names).
    A directory that cannot be listed, and the files that cannot be looked up, are returned
    as they are, and scan() reports them."""
    if os.path.isdir(path):
        try:
            names = sorted(os.listdir(path))
        except OSError:
            return [path]
        files = [os.path.join(path, n) for n in names if HASHED_NAME.match(n)]
        return [f for f in files if os.path.isfile(f) or denied(f)]
    return [path]


def check_sources(item, sources, actions):
    """Check CA lists. sources: [(label, paths, where)]. actions: {label: action if it fails}."""
    bad, counts, unread, unclear, failed, broken = [], [], [], [], [], []
    for label, paths, where in sources:
        hits, count, odd, errors, unloaded = scan([p for p in paths if p])
        broken += ['%s (%s)' % (path, why) for path, why in unloaded.items()]
        counts.append('%d in %s' % (count, where))
        if count == 0 and not unloaded:
            unread.append('%s (%s)' % (label, where or 'none'))
        else:                         # some files of the list could be read, but not all of them
            failed += ['%s (%s)' % (path, why) for path, why in errors.items()]
        if hits:
            bad.append((label, sorted(set().union(*hits.values())), where))
        for path, names in odd.items():
            unclear.append('%s (%s)' % (', '.join(sorted(names)), path))
    if bad or broken:
        if len(sources) == 1 and not broken:
            detail = 'still trusts %s (%s)' % (', '.join(bad[0][1]), bad[0][2])
        else:
            detail = '; '.join((['OpenSSL cannot load %s%s, so the HTTPS connections that use it fail'
                                 % (', '.join(broken[:3]), ', ...' if len(broken) > 3 else '')] if broken else []) +
                               ['%s still trusts %s (%s)' % (label, ', '.join(names), where)
                                for label, names, where in bad])
        if unread or failed:
            detail += '; could not read %s' % ', '.join(unread + failed[:3])
        action = ' '.join(dict.fromkeys((['Restore the file that cannot be loaded (e.g. reinstall the package that '
                                          'provides it, or redo the edit), then run this check again.'] if broken else []) +
                                        [actions[label] for label, _, _ in bad]))
        add(FAIL, item, detail, action)
    elif unread:
        add(SKIP, item, 'could not read any certificate from %s' % ', '.join(unread), requested=True)
    elif failed:
        add(SKIP, item, 'could not read %d file(s) of the list: %s%s'
            % (len(failed), ', '.join(failed[:3]), ', ...' if len(failed) > 3 else ''), requested=True)
    elif unclear:
        add(SKIP, item, "found in OpenSSL's trusted format, whose trust settings are not interpreted: %s"
            % ', '.join(unclear), requested=True)
    else:
        add(OK, item, 'distrusted roots not present (certificates: %s)' % ', '.join(counts))


def run(cmd, timeout=60):
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                             universal_newlines=True)
    except Exception as e:
        return None, type(e).__name__
    try:
        out, _ = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        p.kill()
        p.communicate()
        return None, 'TimeoutExpired'
    return p.returncode, out


def version_tuple(v):
    return tuple(int(x) for x in re.findall(r'\d+', v or '')[:3])


def dist_version(name, module):
    """Version as pip shows it (2026.7.22, not 2026.07.22)."""
    try:
        from importlib.metadata import version
        return version(name)
    except Exception:
        v = getattr(module, '__version__', 'unknown')
        return '.'.join(str(int(p)) if p.isdigit() else p for p in v.split('.'))


def import_module(name):
    try:
        return __import__(name)
    except Exception:
        return None


# ---------------------------------------------------------------- environment

def os_store(shell=False, builtin=False):
    """Return (files of the OS CA list used by OpenSSL, short description).

    SSL_CERT_FILE / SSL_CERT_DIR are used on Kompira 2.0, where the daemons get the same
    environment as docker exec, and for programs run from this shell (shell=True, e.g. pip).
    The Kompira 1.6 daemons do not get them from this shell, so OpenSSL's built-in defaults
    are used for them (their own settings are checked by check_daemon_env).
    builtin=True: OpenSSL's built-in defaults, ignoring the variables. git (libcurl) does not
    read SSL_CERT_FILE / SSL_CERT_DIR and uses its built-in CA file, which is taken to be the same.
    """
    vp = ssl.get_default_verify_paths()
    env = os.environ if (context['kompira2'] or shell) and not builtin else {}
    file_var, dir_var = vp.openssl_cafile_env, vp.openssl_capath_env
    # A variable that is set, even to an empty value, replaces OpenSSL's default
    cafile = env[file_var] if file_var in env else vp.openssl_cafile
    capaths = (env[dir_var] if dir_var in env else vp.openssl_capath or '').split(':')
    paths, where = [], []
    if cafile and (os.path.isfile(cafile) or denied(cafile)):    # scan() reports the latter
        paths.append(cafile)
        where.append(cafile)
    for capath in capaths:
        hashed = ca_files(capath) if os.path.isdir(capath) or denied(capath) else []
        if hashed:
            paths += hashed
            where.append(capath + '/')
    if not paths and file_var not in env and dir_var not in env:
        paths = [p for p in ('/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem',
                             '/etc/ssl/certs/ca-certificates.crt', '/etc/ssl/cert.pem')
                 if os.path.isfile(p)]
        where = paths
    return paths, ' + '.join(where)


def kompira_version():
    """Version of the installed Kompira package, from its metadata (no Kompira code is imported)."""
    for name in ('[Kk]ompira', 'kompira_jobmngr'):    # a job manager server has only kompira_jobmngr
        for base in sys.path:
            if not base or not os.path.isdir(base):
                continue
            for meta in glob.glob(os.path.join(base, name + '-*.dist-info')) + \
                    glob.glob(os.path.join(base, name + '-*.egg-info')):
                m = re.match(r'[Kk]ompira(?:_jobmngr)?-(\d[^-]*?)(?:-py[\d.]+)?\.(?:dist|egg)-info$',
                             os.path.basename(meta))
                if m:
                    return m.group(1)
    return None


def environment():
    info = {'python': sys.version.split()[0], 'executable': sys.executable or '-'}
    try:
        with open('/etc/os-release', encoding='utf-8', errors='replace') as f:
            m = re.search(r'^PRETTY_NAME="?([^"\n]*)', f.read(), re.M)
            info['os'] = m.group(1) if m else 'unknown'
    except (OSError, IOError):
        info['os'] = 'unknown'
    kv = kompira_version()
    info['kompira'] = kv or 'unknown (not run with the Kompira Python?)'
    context['kompira2'] = bool(kv and kv.startswith('2.'))
    context['kompira'] = bool(kv) or os.path.exists(KOMPIRA16_PYTHON)
    for name in ('certifi', 'requests', 'pip'):
        mod = import_module(name)
        info[name] = dist_version(name, mod) if mod else None
    try:
        info['root'] = os.geteuid() == 0
    except AttributeError:
        info['root'] = None
    return info


# ---------------------------------------------------------------- checks

def advisory_step(v16, v2, other='See the advisory.'):
    if not context['kompira']:
        return other      # not a Kompira environment (e.g. the Docker host of Kompira 2.0)
    return v2 if context['kompira2'] else v16


def check_python():
    if not context['kompira']:
        add(SKIP, 'Python', 'Kompira is not installed for this Python (%s): the CA lists of Kompira are not checked. '
            'Run it with the Python of Kompira (1.6: %s, 2.0: python in the containers)'
            % (sys.executable, KOMPIRA16_PYTHON), requested=True)
    if os.path.exists(KOMPIRA16_PYTHON) and \
            os.path.realpath(sys.prefix) != os.path.realpath(os.path.dirname(os.path.dirname(KOMPIRA16_PYTHON))):
        add(SKIP, 'Python', 'this is not the Python of Kompira (%s): certifi and pip of Kompira are not checked. '
            'Run it with %s' % (sys.executable, KOMPIRA16_PYTHON), requested=True)
    if OLD_PYTHON:
        add(WARN, 'Python', 'Python %s: the fixed certifi needs Python 3.7 or later' % sys.version.split()[0],
            'Steps 1-A and 1-B of the advisory cannot be used (advisory 4.3); step 2 can still be applied. '
            'Consider updating Kompira.')


def pip_uses_os_store(env):
    """Whether pip uses truststore (the OS CA list): by default on pip 24.2+ unless it is disabled
    with use-deprecated, and when it is enabled with use-feature on pip 22.2 to 24.1 (Python 3.10+ for both)."""
    if not env['pip'] or sys.version_info < (3, 10):
        return False
    ver = version_tuple(env['pip'])
    _, _, truststore, legacy = pip_config()
    return not legacy if ver >= (24, 2) else ver >= (22, 2) and truststore


def in_os_store(path):
    """Whether path is OpenSSL's default CA file or in its default CA directory (the OS CA list)."""
    vp = ssl.get_default_verify_paths()
    real = os.path.realpath(path)
    return bool(vp.openssl_cafile and real == os.path.realpath(vp.openssl_cafile)) or \
        bool(vp.openssl_capath and os.path.realpath(vp.openssl_capath) in (real, os.path.dirname(real)))


def os_store_action(shell=False):
    """What to do with the OS CA list (shell: as seen from this shell, see os_store)."""
    vp = ssl.get_default_verify_paths()
    own = [v for v in (vp.openssl_cafile_env, vp.openssl_capath_env)
           if (context['kompira2'] or shell) and v in os.environ]
    return advisory_step('Apply the OS vendor fix or the interim mitigation (advisory 4.2 step 2).',
                         'Apply step A or B (advisory 4.4).') + (
        ' If %s points to your own file, re-create it from the updated CA lists (advisory 4.5).'
        % ' / '.join(own) if own else '')


def file_action(path, what, os_action=None):
    """What to do with a CA file that still trusts the roots. what: where it is set, e.g. "REQUESTS_CA_BUNDLE".
    os_action: the text to use when the file is the OS CA list."""
    certifi = import_module('certifi')
    if in_os_store(path):
        return os_action or 'This is the OS CA list. ' + os_store_action()
    if certifi and os.path.realpath(path) == os.path.realpath(certifi.where()):
        return OLD_PYTHON_FIX if OLD_PYTHON else advisory_step(
            'This is certifi: update it (advisory 4.2 step 1-A or 1-B).', 'This is certifi: apply step A or B (advisory 4.4).')
    return 'Re-create the file set in %s from the updated CA lists, or remove the setting (advisory 4.5).' % what


def check_os_store(env):
    paths, where = os_store()
    git_paths, git_where = os_store(builtin=True)
    # git (libcurl) does not use SSL_CERT_FILE / SSL_CERT_DIR: when they point elsewhere (Kompira 2.0),
    # the built-in default file that git uses is checked on its own line
    git_apart = set(map(os.path.realpath, git_paths)) != set(map(os.path.realpath, paths))
    users = ('urllib, SMTP, hg' if git_apart else 'urllib, SMTP, git/hg') + (', pip' if pip_uses_os_store(env) else '')
    check_sources('OS CA list (%s)' % users, [('OS CA list', paths, where)], {'OS CA list': os_store_action()})
    if git_apart:
        check_sources('OS CA list for git (built-in default; git does not use SSL_CERT_FILE / SSL_CERT_DIR)',
                      [('OS CA list', git_paths, git_where)],
                      {'OS CA list': advisory_step('Apply the OS vendor fix or the interim mitigation (advisory 4.2 step 2).',
                                                   'Apply step A or B (advisory 4.4).')})


def requests_bundle():
    """(variable, path) of the CA list that requests uses instead of certifi in this environment."""
    for var in ('REQUESTS_CA_BUNDLE', 'CURL_CA_BUNDLE'):
        if os.environ.get(var):
            return var, os.environ[var]
    return None, None


def check_certifi_requests(env):
    certifi = import_module('certifi')
    # The Kompira 1.6 daemons do not get REQUESTS_CA_BUNDLE of this shell (their settings are checked
    # by check_daemon_env); the containers of Kompira 2.0 get the same environment as docker exec.
    var, bundle = requests_bundle() if context['kompira2'] else (None, None)
    if not certifi:
        add(SKIP, 'certifi', 'not installed in this Python')
    elif bundle and env['requests'] and context['kompira2']:
        # requests uses the file in the variable instead of certifi (set for the containers of Kompira 2.0)
        hits, _, unclear, _, _ = scan([certifi.where()])
        names = sorted(set().union(*hits.values(), *unclear.values()))
        add(INFO, 'certifi %s' % env['certifi'], 'not used by requests, as %s is set%s'
            % (var, ' (it still contains %s)' % ', '.join(names) if names else ''))
    else:
        users = ' (Python CA list%s)' % (', used by requests %s' % env['requests']
                                         if env['requests'] and not bundle else '')
        check_sources('certifi %s%s' % (env['certifi'], users), [('certifi', [certifi.where()], certifi.where())],
                      {'certifi': OLD_PYTHON_FIX if OLD_PYTHON else advisory_step(
                          'Update certifi to 2026.10.19 (advisory 4.2 step 1-A or 1-B).',
                          'Apply step A or B (advisory 4.4).')})
    if env['requests'] and bundle:
        check_sources('requests %s (%s)' % (env['requests'], var), [(var, ca_files(bundle), bundle)],
                      {var: file_action(bundle, var)})
    if env['requests'] and (2, 32, 0) <= version_tuple(env['requests']) <= (2, 32, 4):
        add(WARN, 'requests %s' % env['requests'],
            'this version loads the CA list when a process starts: the results above are not used '
            'by the running processes until they are restarted',
            advisory_step('If kompirad, kompira_jobmngrd and httpd have not been restarted since certifi was '
                          'updated, restart them (advisory 4.2).',
                          'If the containers have not been restarted since the update, restart them '
                          '(docker restart keeps the update).'))


def daemon_ca_settings():
    """Return ([(where, variable, value)], [(file, why it cannot be read)]) of the CA settings of the
    Kompira 1.6 daemons: their environment files in /etc/sysconfig, and Environment= of their
    systemd units (e.g. set by systemctl edit). Only these variables are read; the others can
    contain passwords."""
    import shlex
    found, unreadable = [], []
    for daemon in DAEMONS:
        conf = '/etc/sysconfig/' + daemon
        try:
            with open(conf, encoding='utf-8', errors='replace') as f:
                text = f.read()
        except FileNotFoundError:
            text = ''
        except (OSError, IOError) as e:
            text = ''
            unreadable.append((conf, type(e).__name__))
        # [ \t] instead of \s: an empty value must not take the next line (e.g. https_proxy with a password)
        for m in re.finditer(r'^[ \t]*(?:export[ \t]+)?(%s)[ \t]*=[ \t]*(["\']?)(.*?)\2[ \t\r]*$'
                             % '|'.join(CA_ENV_VARS), text, re.M):
            if m.group(3):
                found.append((conf, m.group(1), m.group(3)))
        if shutil.which('systemctl'):
            rc, out = run(['systemctl', 'show', '-p', 'Environment', daemon + '.service'], 10)
            try:
                words = shlex.split(out.strip()[len('Environment='):]) if rc == 0 else []
            except ValueError:
                words = []
            for word in words:
                var, _, value = word.partition('=')
                if var in CA_ENV_VARS and value:
                    found.append(('the systemd unit %s' % daemon, var, value))
    return found, unreadable


def check_daemon_env():
    found, unreadable = daemon_ca_settings()
    for conf, why in unreadable:
        add(SKIP, 'CA settings in %s' % conf, 'cannot read it (%s); run as root' % why, requested=True)
    for conf, var, value in found:
        dirs = value.split(':') if var == 'SSL_CERT_DIR' else [value]   # OpenSSL takes a list of directories
        check_sources('%s in %s' % (var, conf), [(var, [p for d in dirs for p in ca_files(d)], value)],
                      {var: 'Update the file set in %s, or remove the setting, then restart the daemon.' % var})


def pip_config():
    """The cert files configured for pip (any section, PIP_CERT), whether one of them
    applies to every pip command ([global] or PIP_CERT), whether truststore is enabled
    (use-feature in any section, PIP_USE_FEATURE), and whether it is disabled for every pip
    command (use-deprecated = legacy-certs, see below)."""
    # As pip (platformdirs) does: the XDG variables replace the default directories
    xdg_dirs = (os.environ.get('XDG_CONFIG_DIRS') or '/etc/xdg').split(':')
    xdg_homes = [os.environ.get('XDG_CONFIG_HOME') or os.path.expanduser('~/.config')]
    config_file = os.environ.get('PIP_CONFIG_FILE')
    # As pip does: no configuration file is read when PIP_CONFIG_FILE is os.devnull, and the
    # user's files are not read when PIP_CONFIG_FILE exists.
    files = []
    if config_file != os.devnull:
        files = ([config_file] if config_file else []) + \
            [os.path.join(d, 'pip', 'pip.conf') for d in dict.fromkeys(xdg_dirs) if d] + ['/etc/pip.conf']
        if not (config_file and os.path.exists(config_file)):
            files += [os.path.expanduser('~/.pip/pip.conf')] + \
                [os.path.join(d, 'pip', 'pip.conf') for d in dict.fromkeys(xdg_homes) if d]
        files.append(os.path.join(sys.prefix, 'pip.conf'))
    import configparser
    certs, everywhere, truststore, deprecated = [], False, False, []
    for f in files:
        cp = configparser.RawConfigParser()
        try:
            cp.read(f, encoding='utf-8')
        except Exception:
            continue
        for section in cp.sections():                   # [global] and the sections of each command
            if cp.has_option(section, 'cert'):
                certs.append(cp.get(section, 'cert'))   # only cert, use-feature and use-deprecated are read
                everywhere = everywhere or section == 'global'
            if cp.has_option(section, 'use-feature'):
                truststore = truststore or 'truststore' in cp.get(section, 'use-feature').split()
            if cp.get(section, 'use-deprecated', fallback=''):
                deprecated.append((section, cp.get(section, 'use-deprecated').split()))
    if os.environ.get('PIP_CERT'):
        certs.append(os.environ['PIP_CERT'])
        everywhere = True
    truststore = truststore or 'truststore' in os.environ.get('PIP_USE_FEATURE', '').split()
    # A later setting replaces an earlier one: [<command>] replaces [global] for the command, and
    # PIP_USE_DEPRECATED replaces both. So legacy-certs is taken only when no setting can drop it.
    if os.environ.get('PIP_USE_DEPRECATED'):
        legacy = 'legacy-certs' in os.environ['PIP_USE_DEPRECATED'].split()
    else:
        legacy = any(section == 'global' for section, _ in deprecated) and \
            all('legacy-certs' in features for _, features in deprecated)
    return list(dict.fromkeys(os.path.expanduser(c) for c in certs)), everywhere, truststore, legacy


def check_pip(env):
    try:
        from pip._vendor import certifi as pip_certifi
    except Exception:
        add(SKIP, 'pip', 'pip is not available in this Python')
        return
    ver = env['pip']
    certs, everywhere, _, _ = pip_config()
    var, bundle = requests_bundle()
    # Python 3.10+ and pip 24.2+ (truststore, unless legacy-certs): the bundled certifi and the OS CA list,
    # plus the cert file or REQUESTS_CA_BUNDLE if set.
    # pip 22.2 to 24.1 with truststore enabled (use-feature): the OS CA list, plus what pip uses without it.
    # Otherwise, as in requests: REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE if set (it takes precedence over the
    # cert file while requests reads the environment), else the cert file if set (for the commands it
    # applies to), else the bundled certifi. The files that can be used are checked together.
    # The cert file and the bundled certifi are left out because of REQUESTS_CA_BUNDLE only where pip
    # surely reads it (bundle_first):
    # - pip 24.1+ stops reading the environment when a proxy is set (pip.conf, PIP_PROXY or --proxy,
    #   which this script cannot see), so pip 24.1+ is not trusted to use the variable (this is not the
    #   24.2 boundary of truststore above);
    # - only on Kompira 2.0, where the variable comes from the container environment and also applies to
    #   pip run by docker exec. On Kompira 1.6 it may be set only in the shell running this script.
    truststore = pip_uses_os_store(env)
    with_certifi = truststore and version_tuple(ver) >= (24, 2)    # pip 24.2+ loads it into truststore
    pip_ver = version_tuple(ver)    # () when unknown: not taken as older than 24.1
    bundle_first = bool(bundle) and context['kompira2'] and bool(pip_ver) and pip_ver < (24, 1)
    os_action = os_store_action(shell=True)          # pip is run from this shell
    sources, actions = [], {}
    if bundle_first:
        certs = []
    for cert in certs:
        sources.append(('the cert file of pip', ca_files(cert), cert))
    if certs:
        actions['the cert file of pip'] = ' '.join(dict.fromkeys(file_action(c, 'the cert of pip', os_action)
                                                                  for c in certs))
    if bundle:
        sources.append((var, ca_files(bundle), bundle))
        actions[var] = file_action(bundle, var, os_action)
    if with_certifi or not (everywhere or bundle_first):
        sources.append(("pip's bundled certifi", [pip_certifi.where()], pip_certifi.where()))
        if OLD_PYTHON:
            fix = OLD_PYTHON_FIX
        elif version_tuple(ver) >= FIXED_PIP:
            fix = 'Reinstall pip %s.' % '.'.join(map(str, FIXED_PIP))
        elif sys.version_info >= (3, 10):
            fix = advisory_step('Update pip to 26.2.2 (advisory 4.2 step 1-A).',
                                'Update pip to 26.2.2 (advisory 4.4 step A; step B does not update pip).')
        else:
            fix = 'Set pip global.cert to the updated certifi (advisory 4.2 step 1-B).'
        actions["pip's bundled certifi"] = fix
    if truststore:
        paths, where = os_store(shell=True)
        sources.append(('the OS CA list', paths, where))
        actions['the OS CA list'] = os_action
    uses = ' + '.join(dict.fromkeys(label.replace('the ', '') for label, _, _ in sources))
    check_sources('pip %s (uses %s)' % (ver, uses), sources, actions)


def check_interim():
    found = []
    for d in ('blocklist', 'blacklist'):
        for f in ('Comodo_AAA_Services_root.pem', 'emSign_ECC_Root_CA_-_G3.pem'):
            if os.path.isfile('/etc/pki/ca-trust/source/%s/%s' % (d, f)):
                found.append('/etc/pki/ca-trust/source/%s/%s' % (d, f))
    if found:
        add(INFO, 'Interim mitigation', 'present: ' + ', '.join(found),
            'Keep them until the OS vendor fix is applied, then remove them (advisory 4.2 step 2; '
            'the fixed versions are in advisory 3).')
    if os.path.isfile('/etc/ca-certificates.conf'):
        with open('/etc/ca-certificates.conf', encoding='utf-8', errors='replace') as fp:
            if re.search(r'^!mozilla/(emSign_ECC_Root_CA_-_G3|Comodo_AAA_Services_root)\.crt', fp.read(), re.M):
                add(INFO, 'Interim mitigation', 'present: /etc/ca-certificates.conf (!mozilla/...)',
                    'This change is lost when the container is recreated. '
                    'After recreating a container, apply step A or B again (advisory 4.4).')


def conf_files(directory, unreadable):
    """Return the *.conf files in a settings directory. glob() would hide why it cannot be listed."""
    try:
        names = os.listdir(directory)
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as e:
        unreadable.append((directory, type(e).__name__))
        return []
    return sorted(os.path.join(directory, n) for n in names if n.endswith('.conf') and not n.startswith('.'))


def server_cert_files():
    """Return ([server certificate files in the Apache / RabbitMQ settings],
    [(settings file or directory, why it cannot be read)])."""
    files, unreadable, server_root = [], [], '/etc/httpd'
    arg = r'[ \t]+(?:"([^"\n]+)"|\'([^\'\n]+)\'|([^\s"\']\S*))'   # Apache: one argument, quoted if it has spaces
    try:
        with open('/etc/httpd/conf/httpd.conf', encoding='utf-8', errors='replace') as f:
            m = re.search(r'^[ \t]*ServerRoot' + arg, f.read(), re.M | re.I)
            server_root = ''.join(m.groups('')) if m else server_root
    except (OSError, IOError):
        pass
    for conf in conf_files('/etc/httpd/conf.d', unreadable) + ['/etc/httpd/conf/httpd.conf']:
        try:
            with open(conf, encoding='utf-8', errors='replace') as f:
                for m in re.finditer(r'^[ \t]*SSLCertificate(?:Chain)?File' + arg, f.read(), re.M | re.I):
                    files.append(os.path.join(server_root, ''.join(m.groups(''))))   # relative to ServerRoot
        except FileNotFoundError:
            pass
        except (OSError, IOError) as e:
            unreadable.append((conf, type(e).__name__))
    for conf in ['/etc/rabbitmq/rabbitmq.conf'] + conf_files('/etc/rabbitmq/conf.d', unreadable):
        try:
            with open(conf, encoding='utf-8', errors='replace') as f:
                # RabbitMQ: the value runs to the end of the line or a comment, and may have spaces
                for m in re.finditer(r'^[ \t]*ssl_options\.certfile[ \t]*=[ \t]*([^#\n]*[^#\s])', f.read(), re.M):
                    files.append(m.group(1))
        except FileNotFoundError:
            pass
        except (OSError, IOError) as e:
            unreadable.append((conf, type(e).__name__))
    return files, unreadable


def der_item(buf, pos, expect=None):
    """Return (tag, start, end) of the contents of the DER item at pos.
    ValueError if it runs past the end of buf, or if its tag is not expect."""
    tag, length = buf[pos], buf[pos + 1]
    pos += 2
    if length & 0x80:
        size = length & 0x7f
        length = int.from_bytes(buf[pos:pos + size], 'big')
        pos += size
    if pos + length > len(buf) or (expect is not None and tag != expect):
        raise ValueError('malformed DER')
    return tag, pos, pos + length


SEQUENCE, INTEGER = 0x30, 0x02


def cert_fields(der):
    """Return (issuer, validity) of a certificate as DER bytes (ValueError / IndexError if malformed)."""
    _, start, _ = der_item(der, 0, SEQUENCE)            # Certificate
    _, pos, _ = der_item(der, start, SEQUENCE)          # TBSCertificate
    tag, _, end = der_item(der, pos)
    if tag == 0xa0:                                     # [0] version
        _, _, end = der_item(der, end, INTEGER)         # serialNumber
    elif tag != INTEGER:
        raise ValueError('malformed certificate')
    _, _, start = der_item(der, end, SEQUENCE)          # signature algorithm
    _, _, end = der_item(der, start, SEQUENCE)          # issuer
    _, _, vend = der_item(der, end, SEQUENCE)           # validity
    return der[start:end], der[end:vend]


def issuer_of(der):
    return cert_fields(der)[0]


def validity(der):
    """Return (notBefore, notAfter) of a certificate (UTC)."""
    seq = cert_fields(der)[1]
    _, pos, _ = der_item(seq, 0, SEQUENCE)
    times = []
    for _ in range(2):
        tag, start, pos = der_item(seq, pos)  # UTCTime or GeneralizedTime
        fmt = '%y%m%d%H%M%SZ' if tag == 0x17 else '%Y%m%d%H%M%SZ'
        times.append(datetime.datetime.strptime(seq[start:pos].decode('ascii'), fmt).replace(
            tzinfo=datetime.timezone.utc))
    return tuple(times)


def issued_by_emudhra(ders):
    """Whether any of the certificates was issued by eMudhra (emSign). None: not known, as a
    certificate cannot be parsed and eMudhra is not found in it either."""
    unknown = False
    for der in ders:
        try:
            issuer = issuer_of(der)
        except (IndexError, ValueError):
            issuer, unknown = der, True       # cannot parse: look at the whole certificate
        if any(marker in issuer for marker in EMUDHRA_MARKERS):
            return True
    return None if unknown else False


def check_server_cert_file(path, explicit):
    """explicit: given with --cert, or --certs-only was given (then a file that cannot be checked is a SKIP)."""
    item = 'Server certificate %s' % path
    try:
        ders = pem_certs(path)
    except (OSError, IOError) as e:
        if explicit:
            add(SKIP, item, 'cannot read (%s)' % type(e).__name__, requested=True)
        else:
            add(INFO, item, 'found in the server settings, but cannot read it (%s)' % type(e).__name__,
                'Run as root to check it.' if isinstance(e, PermissionError) and os.geteuid() != 0 else '')
        return
    if not ders:
        if explicit:
            add(SKIP, item, 'no certificate found', requested=True)
        else:
            add(INFO, item, 'found in the server settings, but no certificate (PEM) found in it')
        return
    report_server_cert(item, ders, explicit)


def report_server_cert(item, ders, explicit=True):
    # Other eMudhra roots (e.g. emSign Root CA - G1) stay trusted: only certificates under the
    # distrusted roots are affected (an eMudhra intermediate CA is also signed by AAA Certificate
    # Services), and the chain is not followed here.
    found = issued_by_emudhra(ders)
    if found:
        add(WARN, item, 'issued by eMudhra (emSign)',
            'If it chains to %s, clients that update their CA lists will reject it. '
            'Ask the CA, and re-issue it from another CA if so.' % ' or '.join(sorted(DISTRUSTED_ROOTS.values())))
    elif found is None:
        if explicit:
            add(SKIP, item, 'cannot parse the certificate', requested=True)
        else:
            add(INFO, item, 'found in the server settings, but cannot parse the certificate')
    else:
        add(OK, item, 'not issued by eMudhra (emSign)')


class ProxyNotSupported(Exception):
    """The proxy setting cannot be used here. The message never contains the setting itself."""


def proxy_for(host):
    """The proxy for https to host, decided as in urllib and requests (None: connect directly)."""
    import urllib.request
    if urllib.request.proxy_bypass(host):
        return None
    return urllib.request.getproxies().get('https')


def parse_proxy(proxy):
    """Return (host, port, user, password) of an http:// proxy; ProxyNotSupported for others."""
    from urllib.parse import urlsplit, unquote
    # Never show the error message here: it can contain a part of the password.
    try:
        u = urlsplit(proxy if '://' in proxy else 'http://' + proxy)
        scheme, host, port = u.scheme, u.hostname, u.port or 80
    except ValueError:
        scheme, host = 'http', None
    if scheme != 'http':
        raise ProxyNotSupported('only http:// proxies are supported')
    if not host:
        raise ProxyNotSupported('cannot read the proxy setting; write "#", "/", "?" and "@" in the user name '
                                'and the password as %23, %2F, %3F and %40')
    return host, port, unquote(u.username) if u.username else None, unquote(u.password or '')


def peer_cert_unverified(host, port=443, timeout=10, use_proxy=False):
    """Return the DER of the certificate presented by host (not verified, nothing is sent)."""
    import http.client
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    proxy = proxy_for(host) if use_proxy else None
    if proxy:
        proxy_host, proxy_port, user, password = parse_proxy(proxy)
        conn = http.client.HTTPSConnection(proxy_host, proxy_port, timeout=timeout, context=ctx)
        headers = {}
        if user:
            token = base64.b64encode(('%s:%s' % (user, password)).encode())
            headers['Proxy-Authorization'] = 'Basic ' + token.decode()
        conn.set_tunnel(host, port, headers)
        conn.connect()
        try:
            return conn.sock.getpeercert(binary_form=True)
        finally:
            conn.close()
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            return tls.getpeercert(binary_form=True)


def check_server_host(spec):
    from urllib.parse import urlsplit
    item = 'Server certificate of %s' % spec
    try:
        u = urlsplit('//' + spec)             # HOST, HOST:PORT, [IPv6] or [IPv6]:PORT
        host, port = u.hostname, u.port or 443
    except ValueError:
        host = None
    if not host:
        add(SKIP, item, 'cannot read the host (write an IPv6 address as [ADDRESS]:PORT)', requested=True)
        return
    try:
        der = peer_cert_unverified(host, port)
    except Exception as e:
        add(SKIP, item, 'cannot connect (%s)' % type(e).__name__, requested=True)
        return
    report_server_cert(item, [der])


# OpenSSL's reasons that mean the CA list does not trust the issuer
UNTRUSTED = ('unable to get local issuer certificate', 'unable to get issuer certificate',
             'self signed certificate in certificate chain', 'self-signed certificate in certificate chain',
             'certificate not trusted', 'certificate rejected')


def classify(exc):
    """Return (OK, reason) if the certificate was rejected as its issuer is not trusted,
    (SKIP, reason) if it was rejected for another reason, and (SKIP, None) otherwise."""
    text = '%s %r' % (exc, exc)
    if 'CERTIFICATE_VERIFY_FAILED' not in text and 'certificate verify failed' not in text:
        return SKIP, None
    m = re.search(r'certificate verify failed: ([^(\'"\\]+)', text)
    if not m:
        return OK, None                       # Python 3.6 does not tell the reason
    reason = m.group(1).strip().rstrip('.')
    return (OK if reason in UNTRUSTED else SKIP), reason[:100]


def check_online():
    import urllib.error
    import urllib.request
    # The proxy settings are checked before any connection: urllib would send the credentials
    # for an https:// proxy in plain text.
    try:
        for host in ('pypi.org',) + TEST_SITES:
            if proxy_for(host):
                parse_proxy(proxy_for(host))
    except ProxyNotSupported as e:
        add(SKIP, 'Online checks', 'not run (%s)' % e, requested=True)
        return

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *args, **kwargs):
            return None               # a redirect raises HTTPError; the proxy for its target is not checked above

    def head(url, ctx=None):
        """The response headers of url (those of a redirect, which is not followed)."""
        opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
        try:
            with opener.open(urllib.request.Request(url, method='HEAD'), timeout=10) as resp:
                return resp.headers
        except urllib.error.HTTPError as e:
            return e.headers

    # clock: with a wrong clock, a certificate that is not valid yet is rejected for that reason
    clock_wrong = False
    try:
        try:
            headers = head('https://pypi.org/')
        except Exception:
            headers = head('https://pypi.org/', ssl._create_unverified_context())
        server = email.utils.parsedate_to_datetime(headers['Date'])
        skew = (datetime.datetime.now(datetime.timezone.utc) - server).total_seconds()
        if abs(skew) > 600:
            clock_wrong = True
            add(WARN, 'System clock', 'differs from the Internet time by %d seconds' % skew,
                'Fix the clock, then run the online checks again.')
        else:
            add(OK, 'System clock', 'within %d seconds of the Internet time' % abs(skew))
    except Exception as e:
        add(SKIP, 'System clock', 'cannot check (%s)%s' % (type(e).__name__, NO_NETWORK_HINT), requested=True)

    # A test site is meaningful only while it presents its own certificate (issued by the leaked
    # intermediate CA) and the certificate has not expired: otherwise an error says nothing about the CA lists.
    sites, intercepted, expired = [], False, False
    for host in TEST_SITES:
        try:
            der = peer_cert_unverified(host, use_proxy=True)
        except Exception as e:
            add(SKIP, 'Test site %s' % host, 'not checked: cannot connect (%s)%s'
                % (type(e).__name__, NO_NETWORK_HINT), requested=True)
            continue
        if not issued_by_emudhra([der]):
            intercepted = True
            continue
        try:
            not_before, not_after = validity(der)
            now = datetime.datetime.now(datetime.timezone.utc)
            if now < not_before:
                clock_wrong = True        # behind: the rejection would be "not yet valid"
            elif not_after < now:
                expired = True
                continue
        except (IndexError, ValueError):
            pass
        sites.append(host)
    if intercepted:
        add(WARN, 'TLS interception', 'the test sites do not present certificates issued by eMudhra: '
            'a proxy may re-sign them, or the sites may have changed their certificates',
            'If a proxy re-signs them, the proxy must also update its CA list.')
        add(SKIP, 'Test sites', 'not checked, as the results would not be reliable', requested=True)
        return
    if not (sites or expired):
        return                        # no test site could be reached (see the lines above)
    add(OK, 'TLS interception', 'not detected (the test sites present their own certificates)')
    if clock_wrong:
        add(SKIP, 'Test sites', 'not checked, as the system clock is wrong', requested=True)
        return
    if expired:
        add(SKIP, 'Test sites', 'their certificates have expired, so they cannot show whether the fake '
            'certificate is rejected (the checks of the CA lists above are not affected)', requested=True)
        return

    # On Kompira 2.0 the daemons get the same environment as docker exec. The Kompira 1.6 daemons do
    # not get SSL_CERT_FILE / SSL_CERT_DIR / REQUESTS_CA_BUNDLE of this shell (see os_store), so the
    # probes use OpenSSL's defaults and certifi there.
    https, broken = urllib.request.HTTPSHandler(), None
    certifi = import_module('certifi')
    verify = certifi.where() if certifi else True
    if context['kompira2']:
        verify = requests_bundle()[1] or verify
    else:
        vp = ssl.get_default_verify_paths()
        try:
            ctx = ssl.create_default_context(
                cafile=vp.openssl_cafile if vp.openssl_cafile and os.path.isfile(vp.openssl_cafile) else None,
                capath=vp.openssl_capath if vp.openssl_capath and os.path.isdir(vp.openssl_capath) else None)
            https = urllib.request.HTTPSHandler(context=ctx)
        except OSError as e:                  # a broken OS CA list (reported above as FAIL)
            broken = getattr(e, 'reason', None) or str(e)[:80] or type(e).__name__
    opener = urllib.request.build_opener(NoRedirect, https)
    # Only the response headers are read: a site whose certificate is accepted can send an endless body.
    tests = [('urllib (OS CA list)', lambda url: opener.open(url, timeout=10).close())]
    if broken:
        tests = []
        add(SKIP, 'Online: urllib (OS CA list)', 'not checked: OpenSSL cannot load the OS CA list (%s)' % broken,
            requested=True)
    try:
        import requests
        from urllib.parse import urlsplit
        # Nothing is taken from the environment (all_proxy, ~/.netrc, REQUESTS_CA_BUNDLE): requests
        # uses the same proxy as the certificate check above and urllib, and the CA list given here.
        session = requests.Session()
        session.trust_env = False

        def via_requests(url):
            proxy = proxy_for(urlsplit(url).hostname)
            session.get(url, timeout=10, allow_redirects=False, stream=True, verify=verify,
                        proxies={'https': proxy} if proxy else {}).close()
        tests.insert(0, ('requests', via_requests))
    except Exception:
        pass
    for host in sites:
        url = 'https://%s/' % host
        for name, get in tests:
            item = 'Online: %s -> %s' % (name, host)
            try:
                get(url)
                connected = True
            except urllib.error.HTTPError:
                connected = True      # the TLS handshake succeeded; the server answered with an HTTP error
            except Exception as e:
                connected = False
                status, reason = classify(e)
                if status == OK:
                    add(OK, item, 'rejected (CERTIFICATE_VERIFY_FAILED%s)' % (': ' + reason if reason else ''))
                elif reason:
                    add(SKIP, item, 'rejected for another reason (%s), which does not show whether the CA list '
                        'trusts the roots' % reason, requested=True)
                else:
                    add(SKIP, item, 'could not check (%s)%s' % (type(e).__name__, NO_NETWORK_HINT),
                        requested=True)
            if connected:
                add(FAIL, item, 'connected (the fake certificate was accepted)',
                    'Apply the procedures in the advisory.')
    # pip is not run here: it may run the build code of a package served by the test site.
    # Its CA lists are checked by the fingerprints above.


# ---------------------------------------------------------------- output

NOTE = ('NOTE: Some Kompira functions do not verify server certificates at all '
        '(mail receiving (IMAP/POP3), LDAP authentication, SMTP without OAuth2 on 2.0, '
        'urlopen without verify=True, windows/https-ignore-validation, AMQP without TLS, and AMQPS by default). '
        'They can be spoofed regardless of this incident, and updating the CA lists does '
        'not make them safe. ' + ADVISORY)


def verdict(certs_only=False):
    fails = sum(r['status'] == FAIL for r in results)
    if fails:
        return FAIL, 'ACTION REQUIRED - %d problem(s) found' % fails
    if not any(r['status'] in (OK, WARN) for r in results):
        return SKIP, 'UNKNOWN - nothing could be checked'
    skipped = sum(r['status'] == SKIP and r['requested'] for r in results)
    if skipped:
        return SKIP, 'INCOMPLETE - no problem found, but %d check(s) could not run (see [SKIP])' % skipped
    if any(r['status'] == WARN for r in results):
        return WARN, 'CHECK THE WARNINGS - no problem found, but see [WARN]'
    if certs_only:
        return OK, 'OK - no server certificate was issued by eMudhra (emSign)'
    return OK, 'OK - no distrusted root certificate is trusted'


def main():
    ap = argparse.ArgumentParser(description='Kompira CA trust self-check (eMudhra / emSign incident)')
    ap.add_argument('--online', action='store_true')
    ap.add_argument('--cert', action='append', default=[])
    ap.add_argument('--host', action='append', default=[])
    ap.add_argument('--certs-only', action='store_true')
    ap.add_argument('--json', action='store_true')
    ap.add_argument('--no-color', action='store_true')
    args = ap.parse_args()
    if args.certs_only and args.online:
        ap.error('--online cannot be used with --certs-only')

    env = environment()
    if not args.certs_only:
        check_python()
        check_os_store(env)
        check_certifi_requests(env)
        check_daemon_env()
        check_pip(env)
        check_interim()
    explicit = {os.path.realpath(p) for p in args.cert}
    found, unreadable = server_cert_files()
    for conf, why in unreadable:
        detail = 'cannot read it (%s), so the server certificates set in it are not checked' % why
        if args.certs_only:
            add(SKIP, 'Server settings %s' % conf, detail + '; run as root', requested=True)
        else:
            add(INFO, 'Server settings %s' % conf, detail, 'Run as root to check them.')
    for path in dict.fromkeys(found):
        if os.path.realpath(path) not in explicit:
            check_server_cert_file(path, args.certs_only)
    for path in args.cert:
        check_server_cert_file(path, True)
    for spec in args.host:
        check_server_host(spec)
    if args.certs_only:
        if not any(r['item'].startswith(('Server certificate', 'Server settings')) for r in results):
            add(SKIP, 'Server certificate', 'nothing to check (give --cert or --host)', requested=True)
    elif args.online:
        check_online()
    else:
        add(INFO, 'Online checks', 'not run (no network connection was made)',
            'Run with --online to also test against the public test sites.')
    status, summary = verdict(args.certs_only)

    if args.json:
        print(json.dumps({'tool': TOOL_VERSION, 'environment': env, 'result': status,
                          'summary': summary, 'checks': results}, indent=2))
        return status

    color = not args.no_color and sys.stdout.isatty() and os.environ.get('TERM') != 'dumb'

    def paint(code, text):
        return '\033[%sm%s\033[0m' % (code, text) if color else text

    bar = '=' * 72
    banner = paint(COLORS[status], '  RESULT: %s  %s' % (LABELS[status], summary))
    print(bar)
    print(banner)
    print(bar)
    print('kompira-ca-check %s  |  Kompira %s  |  Python %s  |  %s'
          % (TOOL_VERSION, '-' if args.certs_only else env['kompira'], env['python'], env['os']))
    if args.certs_only:
        print('--certs-only: only the server certificates are checked, not the CA lists of this machine')
    else:
        print('certifi %s  |  requests %s  |  pip %s'
              % (env['certifi'] or '-', env['requests'] or '-', env['pip'] or '-'))
    print('run as: %s%s  |  %s'
          % (env['executable'], '' if env['root'] is not False else ' (not root: some files may not be readable)',
             datetime.datetime.now(datetime.timezone.utc).strftime('%Y-%m-%d %H:%M UTC')))
    print('-' * 72)
    for r in results:
        print('%s %s: %s' % (paint(COLORS[r['status']], LABELS[r['status']]), r['item'], r['detail']))
        if r['action'] and r['status'] in (FAIL, WARN, INFO):
            print('       -> %s' % r['action'])
    print('-' * 72)
    print(NOTE)
    print(bar)
    print(banner)
    print(bar)
    return status


if __name__ == '__main__':
    try:
        final = main()
    except Exception as e:
        # Only the type and the line: the message can contain a setting such as the proxy password.
        lines = [f.lineno for f in traceback.extract_tb(e.__traceback__) if f.filename == main.__code__.co_filename]
        print('ERROR: the check stopped unexpectedly (%s at line %s). Nothing was changed.'
              % (type(e).__name__, lines[-1] if lines else '?'), file=sys.stderr)
        sys.exit(2)
    sys.exit({OK: 0, WARN: 0, FAIL: 1}.get(final, 2))
