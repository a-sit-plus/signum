#!/usr/bin/env python3
"""Import pinned upstream certificate tests. Normal JVM runs use only the committed JSON.

Usage: python3 import_corpora.py --cache /tmp/signum-public-corpora
Requires Python stdlib, curl, and Go (only to materialize Go's generated fixtures).
No private keys or upstream build tools are committed.
"""
import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tarfile
import tempfile
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
OUTPUT = HERE.parent / 'resources' / 'corpora'
PINS = {
    'boringssl': ('google/boringssl', '5d165bc0408b977a80247598834cddd2c99b788f'),
    'openssl': ('openssl/openssl', '21909a8a544f88d162ce1d2929cdad5ff990fe11'),
    'go': ('golang/go', 'a0c8470e9dfe38ac3b594f944238a5678fe9a07e'),
}
PEM = re.compile(r'-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+?)-----END CERTIFICATE-----')
certificates, cases, exclusions = {}, [], []


def download(url, path):
    if not path.exists():
        subprocess.run(['curl', '--fail', '--silent', '--show-error', '--location', '--retry', '2',
                        '--max-time', '120', url, '-o', str(path)], check=True)
    return path


def raw(cache, source, path):
    repo, commit = PINS[source]
    target = cache / source / path
    target.parent.mkdir(parents=True, exist_ok=True)
    return download(f'https://raw.githubusercontent.com/{repo}/{commit}/{path}', target).read_text()


def archive(cache, source):
    repo, commit = PINS[source]
    path = download(f'https://codeload.github.com/{repo}/tar.gz/{commit}', cache / f'{source}.tar.gz')
    files = {}
    with tarfile.open(path) as data:
        for member in data.getmembers():
            root, _, name = member.name.partition('/')
            assert root.endswith(commit), f'Unexpected archive revision: {root}'
            if member.isfile() and (name.startswith('pki/testdata/verify_certificate_chain_unittest/') or
                                   name in ('pki/test_helpers.cc', 'pki/verify_certificate_chain_typed_unittest.h',
                                            'test/recipes/25-test_verify.t', 'LICENSE', 'LICENSE.txt', 'NOTICE') or
                                   name.startswith('test/certs/') and name.endswith('.pem')):
                files[name] = data.extractfile(member).read().decode()
    return files


def cert_refs(text):
    result = []
    for match in PEM.finditer(text):
        body = ''.join(match[1].split())
        pem = '-----BEGIN CERTIFICATE-----\n' + '\n'.join(body[i:i+64] for i in range(0, len(body), 64)) + '\n-----END CERTIFICATE-----\n'
        ref = hashlib.sha256(pem.encode()).hexdigest()
        certificates[ref] = pem
        result.append(ref)
    return result


def source_url(source, path, line=None):
    repo, commit = PINS[source]
    return f'https://github.com/{repo}/blob/{commit}/{path}' + (f'#L{line}' if line else '')


def exclude(source, identifier, reason, url):
    exclusions.append(dict(source=source, id=identifier, reason=reason, sourceUrl=url))


def import_boringssl(files):
    prefix = 'pki/testdata/verify_certificate_chain_unittest/'
    for path, text in sorted(files.items()):
        if not path.startswith(prefix) or not path.endswith('.test'):
            continue
        identifier, url = path[len(prefix):], source_url('boringssl', path)
        header, errors = text.split('expected_errors:\n', 1)
        attrs = dict(line.split(': ', 1) for line in header.splitlines() if line and not line.startswith('#'))
        reason = None
        if attrs['last_cert_trust'] != 'TRUSTED_ANCHOR':
            reason = 'Source-specific anchor expiry/constraints/distrust/direct-leaf trust policy.'
        elif attrs['key_purpose'] not in ('ANY_EKU', 'SERVER_AUTH', 'CLIENT_AUTH'):
            reason = 'Strict TLS, MLS or C2PA purpose policy beyond the RFC5280 preset.'
        elif identifier.startswith('many-names/'):
            reason = 'Source work-limit/resource-exhaustion policy; not an RFC rejection criterion.'
        elif any(word in errors for word in ('extended key usage', 'Unacceptable signature algorithm', 'Unacceptable public key')):
            reason = 'Source CA-EKU propagation or cryptographic-strength policy, not basic path validity.'
        if reason:
            exclude('boringssl', identifier, reason, url)
            continue
        chain_path = str((Path(path).parent / attrs['chain']).as_posix())
        chain = cert_refs(files[chain_path])
        if len(chain) < 2:
            exclude('boringssl', identifier, 'Zero-length/direct-trust target; no nonempty supplied path.', url)
            continue
        validators = []
        for phrase, validator in [
            ('VerifySignedData', 'ChainValidator'), ('subject does not match issuer', 'ChainValidator'),
            ('SubjectPublicKeyInfo', 'ChainValidator'), ('Basic Constraints', 'BasicConstraintsValidator'),
            ('max_path_length', 'BasicConstraintsValidator'), ('keyCertSign', 'KeyUsageValidator'),
            ('Time is', 'TimeValidityValidator'), ('No valid policy', 'PolicyValidator'),
            ('Unconsumed critical extension', 'CriticalCertificateExtensions')]:
            if phrase in errors:
                validators.append(validator)
        expected = 'ERROR: ' not in errors
        assert expected or validators, (identifier, errors)
        utc = attrs['utc_time'] if attrs['utc_time'] != 'DEFAULT' else '211005120000Z'
        when = datetime.strptime(utc, '%y%m%d%H%M%SZ').replace(tzinfo=timezone.utc).isoformat().replace('+00:00', 'Z')
        cases.append(dict(source='boringssl', id=identifier, sourceUrl=url, description=errors.strip() or 'Upstream acceptance control.',
                          expectedValid=expected, anchors=[chain[-1]], paths=[chain[:-1]], validationTime=when,
                          expectedEku={'ANY_EKU': [], 'SERVER_AUTH': ['1.3.6.1.5.5.7.3.1'], 'CLIENT_AUTH': ['1.3.6.1.5.5.7.3.2']}[attrs['key_purpose']],
                          expectedValidators=validators, allowDecodeRejection='SubjectPublicKeyInfo' in errors,
                          allowUnsupportedCryptoAtDecode='SubjectPublicKeyInfo' in errors,
                          upstreamOptions=attrs))


def split_args(text):
    parts, start, depth, quote = [], 0, 0, None
    for i, char in enumerate(text):
        if quote:
            if char == quote and (i == 0 or text[i-1] != '\\'):
                quote = None
        elif char in ('"', "'"):
            quote = char
        elif char in '([{':
            depth += 1
        elif char in ')]}':
            depth -= 1
        elif char == ',' and depth == 0:
            parts.append(text[start:i].strip()); start = i+1
    parts.append(text[start:].strip())
    return [p for p in parts if p]


def literal(text):
    if re.fullmatch(r'"[^"\\]*"', text):
        return text[1:-1]
    raise ValueError('Nonliteral Perl argument')


def perl_list(text):
    if not (text.startswith('[') and text.endswith(']')):
        raise ValueError('Nonliteral Perl list')
    text = text[1:-1].strip()
    if text.startswith('qw(') and text.endswith(')'):
        return text[3:-1].split()
    return [literal(part) for part in split_args(text)]


def import_openssl(files):
    path = 'test/recipes/25-test_verify.t'
    recipe = files[path]
    pattern = r'ok\(\s*(!?)verify\((.*?)\),\s*"([^"\n]+)"\s*\)'
    for match in re.finditer(pattern, recipe, re.S):
        line = recipe[:match.start()].count('\n') + 1
        identifier, url = f'25-test_verify.t:{line}', source_url('openssl', path, line)
        args = split_args(match[2])
        try:
            leaf, purpose = map(literal, args[:2])
            roots = perl_list(args[2])
            untrusted = perl_list(args[3]) if len(args)>3 else []
            options = [literal(arg) for arg in args[4:]]
        except (ValueError, IndexError):
            exclude('openssl', identifier, 'Dynamic/nonliteral Perl setup; not a standalone certificate vector.', url)
            continue
        if purpose:
            exclude('openssl', identifier, 'TLS/purpose/auxiliary-trust policy beyond the basic path preset.', url)
            continue
        allowed = {'-policy_check', '-explicit_policy', '-policy', '-attime', '-inhibit_any', '-inhibit_map'}
        flags, policies, when, reason = set(), [], '2026-11-02T00:00:00Z', None
        i = 0
        while i < len(options):
            flag = options[i]
            if flag not in allowed:
                reason = f'Unsupported OpenSSL option: {flag}'; break
            flags.add(flag)
            if flag in ('-policy', '-attime'):
                i += 1
                value = options[i]
                if flag == '-policy': policies.append(value)
                else: when = datetime.fromtimestamp(int(value), timezone.utc).isoformat().replace('+00:00', 'Z')
            i += 1
        if 'many-' in leaf or 'some-names' in leaf:
            reason = 'Source work-limit/resource-exhaustion policy, not basic path validity.'
        refs = {}
        for name in [leaf] + roots + untrusted:
            pem = files.get(f'test/certs/{name}.pem', '')
            if 'TRUSTED CERTIFICATE' in pem:
                reason = 'OpenSSL auxiliary trust attributes have no representation in this preset.'
            found = cert_refs(pem)
            if len(found) != 1:
                reason = f'Fixture {name} is absent, generated by Perl, or not exactly one ordinary certificate.'
            refs[name] = found
        if not roots or leaf in roots:
            reason = 'No explicit anchor or directly trusted target; not a nonempty supplied path.'
        if reason:
            exclude('openssl', identifier, reason, url); continue
        expected = not bool(match[1])
        desc = match[3]
        if 'only transition cert is trusted' in desc:
            exclude('openssl', identifier, 'OpenSSL requires a self-signed anchor unless -partial_chain is set; RFC 5280 6.1.1(d) permits an explicitly trusted non-self-signed anchor.', url)
            continue
        validators = []
        if not expected:
            if leaf.startswith('badalt') or 'othername' in leaf: validators = ['NameConstraintsValidator']
            elif 'polic' in leaf: validators = ['PolicyValidator']
            elif desc.startswith('Certificate invalid at time '): validators = ['TimeValidityValidator']
            elif 'crit-unknown' in leaf: validators = ['CriticalCertificateExtensions']
            elif 'explicit' in leaf: validators = ['ChainValidator']
            else:
                exclude('openssl', identifier, 'Rejection reason needs manual classification before a failure can count as a pass.', url)
                continue
        cases.append(dict(source='openssl', id=identifier, sourceUrl=url, description=desc,
                          expectedValid=expected, anchors=[refs[r][0] for r in roots],
                          paths=[[refs[leaf][0]] + [refs[n][0] for n in reversed(untrusted)]], validationTime=when,
                          initialPolicies=policies, explicitPolicyRequired='-explicit_policy' in flags,
                          anyPolicyInhibited='-inhibit_any' in flags, policyMappingInhibited='-inhibit_map' in flags,
                          expectedValidators=validators, allowDecodeRejection=not expected and 'explicit' in leaf,
                          upstreamOptions={'purpose': purpose, 'options': ' '.join(options)}))


def import_go(cache):
    path = 'src/crypto/x509/name_constraints_test.go'
    source = raw(cache, 'go', path)
    # Preserve upstream types, tables and certificate generation helpers verbatim.
    body = source[source.index('type nameConstraintsTest struct'):source.index('func TestConstraintCases(')]
    imports = ['crypto/ecdsa', 'crypto/elliptic', 'crypto/rand', 'crypto/x509/pkix', 'encoding/asn1', 'encoding/hex',
               'encoding/json', 'encoding/pem', 'fmt', 'math/big', 'net', 'net/url', 'os', 'runtime', 'strings', 'time']
    program = 'package main\nimport (\n. "crypto/x509"\n' + ''.join(f'"{s}"\n' for s in imports) + ')\n'
    program += body + (HERE / 'export_go.go.txt').read_text()
    export = cache / 'export.go'
    export.write_text(program)
    # Go 1.21's internal linker predates modern macOS LC_UUID requirements; an external linker works there.
    command = ['go', 'run'] + (['-ldflags=-linkmode=external'] if os.uname().sysname == 'Darwin' else []) + [str(export)]
    generated = cache / 'go-generated.json'
    marker = cache / 'go-generated.sha256'
    fingerprint = hashlib.sha256(program.encode()).hexdigest()
    if not generated.exists() or not marker.exists() or marker.read_text() != fingerprint:
        generated.write_bytes(subprocess.check_output(command, env={**os.environ, 'GOTOOLCHAIN':'local', 'GOPROXY':'off'}))
        marker.write_text(fingerprint)
    data = json.loads(generated.read_text())
    for item in data['cases']:
        identifier = f'name_constraints_test.go:{item["index"]:03d}:{item["name"]}'
        url = source_url('go', path)
        if item.get('generationError') or item['policy']:
            exclude('go', identifier, item.get('generationError') or 'Explicit EKU/CA-EKU propagation policy; this import focuses on name constraints.', url)
            continue
        error = item['expectedError']
        cases.append(dict(source='go', id=identifier, sourceUrl=url,
                          description=error or 'Upstream acceptance control.', expectedValid=not bool(error),
                          anchors=[cert_refs(p)[0] for p in item['roots']],
                          paths=[[cert_refs(p)[0] for p in path] for path in item['paths']],
                          validationTime='1970-01-01T00:25:00Z', expectedValidators=['NameConstraintsValidator'] if error else [],
                          allowDecodeRejection=any(word in error.lower() for word in ('cannot parse', 'failed to parse', 'invalid', 'unsupported')), upstreamOptions={'expectedError':error, 'goVersion':data['goVersion']}))
    return data['goVersion']


def check_openssl():
    """Compare the pinned OpenSSL expectations with the installed binary; never rewrite them."""
    corpus = json.loads((OUTPUT/'public-paths.json').read_text())
    mismatches, checked = [], 0
    version = subprocess.check_output(['openssl', 'version'], text=True).strip()
    with tempfile.TemporaryDirectory(prefix='signum-openssl-reference-') as temp:
        directory = Path(temp)
        for ref, pem in corpus['certificates'].items():
            (directory/(ref+'.pem')).write_text(pem)
        for case in corpus['cases']:
            if case['source'] != 'openssl':
                continue
            checked += 1
            roots, chain = directory/'roots.pem', directory/'chain.pem'
            roots.write_text(''.join(corpus['certificates'][r] for r in case['anchors']))
            chain.write_text(''.join(corpus['certificates'][r] for r in case['paths'][0][1:]))
            epoch = str(int(datetime.fromisoformat(case['validationTime'].replace('Z', '+00:00')).timestamp()))
            command = ['openssl', 'verify', '-auth_level', '1', '-attime', epoch, '-trusted', str(roots)]
            if case['paths'][0][1:]:
                command += ['-untrusted', str(chain)]
            command += shlex.split(case['upstreamOptions']['options'])
            command += [str(directory/(case['paths'][0][0]+'.pem'))]
            result = subprocess.run(command, capture_output=True, text=True, timeout=10)
            if (result.returncode == 0) != case['expectedValid']:
                mismatches.append(dict(id=case['id'], sourceUrl=case['sourceUrl'], description=case['description'],
                                       expectedValid=case['expectedValid'], observedValid=result.returncode==0,
                                       diagnostic=(result.stdout+result.stderr).replace(str(directory), '<fixtures>')))
    report = dict(version=version, checked=checked, mismatches=mismatches)
    (OUTPUT/'reference-openssl.json').write_text(json.dumps(report, indent=2)+'\n')
    print(f'Native reference: {version}; {checked} cases; {len(mismatches)} differences (expectations unchanged).')


def record_junit(path):
    """Record observed differences, tied to this exact corpus, without touching its oracle."""
    snapshot = OUTPUT/'public-paths.json'
    corpus = json.loads(snapshot.read_text())
    lookup = {f"{'ACCEPT' if c['expectedValid'] else 'REJECT'} {c['source']}: {c['id']}": c for c in corpus['cases']}
    root = ET.parse(path).getroot()
    failures, counts = [], {}
    tests = root.findall('testcase')
    assert len(tests) == len(lookup), 'JUnit results do not cover this complete corpus'
    for test in tests:
        name = test.attrib['name'].removesuffix('[jvm]').replace('·', '.')
        case = lookup.pop(name)
        stats = counts.setdefault(case['source'], dict(tests=0, passed=0, failures=0, unexpectedAcceptances=0))
        stats['tests'] += 1
        error = test.find('failure')
        if error is None:
            assert test.find('error') is None and test.find('skipped') is None
            stats['passed'] += 1
            continue
        stats['failures'] += 1
        message = error.attrib.get('message', '')
        if not case['expectedValid'] and '\nACCEPTED\n' in message:
            category = 'unexpected-acceptance'
            stats['unexpectedAcceptances'] += 1
        elif 'No loaded ' in message:
            category = 'algorithm-or-decoder-support'
        elif 'Decoding-stage rejection:' in message:
            category = 'decoding-difference'
        elif case['expectedValid']:
            category = 'unexpected-rejection'
        else:
            category = 'wrong-rejection-stage-or-reason'
        failures.append(dict(source=case['source'], id=case['id'], sourceUrl=case['sourceUrl'],
                             expectedValid=case['expectedValid'], category=category,
                             description=case['description'], diagnostic=message[:4096],
                             diagnosticTruncated=len(message)>4096))
    assert not lookup
    report = dict(corpusSha256=hashlib.sha256(snapshot.read_bytes()).hexdigest(),
                  summary=counts, failures=sorted(failures,key=lambda f:(f['source'],f['id'])))
    (OUTPUT/'public-path-results.json').write_text(json.dumps(report, indent=2, ensure_ascii=False)+'\n')
    print(json.dumps(counts,indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cache', type=Path)
    parser.add_argument('--check-openssl', action='store_true', help='Compare existing fixtures against the installed OpenSSL, without importing.')
    parser.add_argument('--record-junit', type=Path, help='Record observed failures from this corpus JUnit XML; expectations stay unchanged.')
    args = parser.parse_args()
    if args.record_junit:
        record_junit(args.record_junit)
        return
    if args.check_openssl:
        check_openssl()
        return
    with tempfile.TemporaryDirectory(prefix='signum-corpora-') as temp:
        cache = args.cache or Path(temp)
        cache.mkdir(parents=True, exist_ok=True)
        boringssl, openssl = archive(cache, 'boringssl'), archive(cache, 'openssl')
        import_boringssl(boringssl)
        import_openssl(openssl)
        go_version = import_go(cache)
        # Do not retain certificates from excluded OpenSSL inputs.
        used = {ref for c in cases for ref in c['anchors']} | {ref for c in cases for p in c['paths'] for ref in p}
        certs = {ref: certificates[ref] for ref in sorted(used)}
        assert len({(c['source'],c['id']) for c in cases}) == len(cases)
        assert all(c['anchors'] and c['paths'] and all(c['paths']) for c in cases)
        OUTPUT.mkdir(parents=True, exist_ok=True)
        data = dict(sources={name:dict(repository=repo, commit=commit) for name,(repo,commit) in PINS.items()},
                    generatorGoVersion=go_version, certificates=certs, cases=cases, exclusions=exclusions)
        (OUTPUT/'public-paths.json').write_text(json.dumps(data, indent=2, ensure_ascii=False)+'\n')
        (OUTPUT/'LICENSE-BoringSSL').write_text(boringssl['LICENSE'])
        (OUTPUT/'LICENSE-OpenSSL').write_text(openssl['LICENSE.txt'])
        (OUTPUT/'LICENSE-Go').write_text(raw(cache, 'go', 'LICENSE'))
        print('Imported',Counter(c['source'] for c in cases),'rejections',Counter(c['source'] for c in cases if not c['expectedValid']))
        print('Excluded',Counter(c['source'] for c in exclusions),'unique certificates',len(certs))


if __name__ == '__main__':
    main()
