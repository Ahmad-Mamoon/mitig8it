#!/usr/bin/env python3
"""Real-provider local HTTP evaluation. Remote observation requires --upload-only."""
from __future__ import annotations
import argparse
import ast
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone
import hashlib
import io
import json
import math
import os
import re
import shutil
from pathlib import Path
import socket
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
REPORT_SCHEMA_VERSION = 2
SOURCE_FILES = ('llm_client.py', 'llm_triage.py', 'main.py', 'analysis_grpc_server.py',
                'grpc/generated/analysis_pb2.py', 'grpc/generated/common_pb2.py')


def now():
    return datetime.now(timezone.utc).isoformat()


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, allow_nan=False).encode()).hexdigest()


def benchmark_rule_ids(cases):
    """Return synthetic IDs admitted only inside the local evaluation process."""
    return frozenset(str(case.get('finding', {}).get('rule_id') or '') for case in cases) - {''}


def source_bindings(cases):
    """Read local inputs only; no service import, provider call, or trust assertion."""
    sources = {name: (ROOT/'services/analysis-service/src'/name).read_text() for name in SOURCE_FILES}
    tree = ast.parse(sources['llm_triage.py'])
    prompt = next(ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and any(isinstance(target, ast.Name) and target.id == 'SYSTEM_PROMPT' for target in node.targets))
    return {'fixture_digest': digest(cases), 'prompt_digest': digest(prompt),
            'source_digest': digest(sources), 'evaluator_digest': digest(Path(__file__).read_text())}


def request_plan(cases, repeats, faults_only=False):
    if type(repeats) is not int or repeats not in (1, 2) or type(faults_only) is not bool:
        raise ValueError('invalid_request_plan')
    ids = [case['id'] for case in cases]
    if not ids or len(set(ids)) != len(ids) or len(ids) * repeats > 12:
        raise ValueError('invalid_request_plan')
    plan = [] if faults_only else [
        {'case_id': case_id, 'mode': 'live', 'repeat': repeat}
        for repeat in range(1, repeats + 1) for case_id in ids]
    return plan + [{'case_id': ids[0], 'mode': mode, 'repeat': 1} for mode in ('timeout', 'malformed')]


def save(path, report):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as stream:
        json.dump(report, stream, indent=2)
        temporary = Path(stream.name)
    temporary.replace(path)


@contextmanager
def environment(values):
    before = {key: os.environ.get(key) for key in values}
    os.environ.update(values)
    try:
        yield
    finally:
        for key, value in before.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def score(case, response, observation):
    """Rubric keyword checks are diagnostic proxies, never a semantic accuracy claim."""
    findings = response.get('findings', [])
    verdicts = observation.get('verdicts', [])
    matching = [v for v in verdicts if v.get('fingerprint') == case['finding']['fingerprint']]
    # The production applicator uses the last verdict for a fingerprint. A
    # duplicate response is still ambiguous and fails the evaluation gate.
    verdict = matching[-1].get('verdict') if matching else None
    advice = next((f.get('evidence_details', {}).get('extra', {}).get('llm_recommendation')
                   for f in findings if f.get('fingerprint') == case['finding']['fingerprint']), None)
    scores = {'verdict_match': int(verdict == case['expected_verdict']),
              'parsed_verdict': int(verdict is not None),
              'unambiguous_verdict': int(len(matching) == 1),
              'one_model_call': int(observation.get('provider_calls') == 1)}
    if case['expected_verdict'] == 'true_positive':
        scores['grounded_recommendation'] = int(bool(advice))
        fix = (advice or {}).get('fix', '').lower()
        groups = case.get('expected_fix_terms', [])
        scores['fix_terms_heuristic'] = int(bool(advice) and all(
            any(term.lower() in fix for term in alternatives) for alternatives in groups))
    return verdict, advice, scores


def replacement_validation(case, observation):
    """Apply and syntax-check an optional raw model proposal, without executing it.

    This is deliberately not remediation verification: no regression test,
    behavior check, sandbox isolation, or GitHub placement is established here.
    """
    result = {'status': 'not_proposed', 'proposal_source': 'raw_model_response',
              'application_checked': False, 'syntax_checked': False,
              'behavior_checked': False, 'sandbox_verified': False,
              'ready_for_inline_publication': False}
    verdicts = [v for v in observation.get('raw_model_verdicts', observation.get('verdicts', []))
                if v.get('fingerprint') == case['finding']['fingerprint']]
    candidate = verdicts[-1].get('fixed_code') if verdicts else None
    if candidate is None or isinstance(candidate, str) and not candidate.strip():
        return result
    result['status'] = 'rejected'
    if not isinstance(candidate, str) or len(candidate) > 2000 or '```' in candidate:
        return {**result, 'reason': 'invalid_replacement_format'}
    replacement = candidate.replace('\r\n', '\n').strip('\n').splitlines()
    if not replacement or len(replacement) > 8:
        return {**result, 'reason': 'replacement_exceeds_line_limit'}
    patch_lines = str(case.get('file_patch', '')).splitlines()
    if not patch_lines:
        return {**result, 'reason': 'complete_added_file_required'}
    header = re.fullmatch(r'@@ -0,0 \+1(?:,(\d+))? @@', patch_lines[0])
    body = patch_lines[1:]
    if (not header or len(body) != int(header.group(1) or 1)
            or not all(line.startswith('+') for line in body)):
        return {**result, 'reason': 'complete_added_file_required'}
    original = [line[1:] for line in body]
    finding = case['finding']
    start, end = finding.get('line_start'), finding.get('line_end', finding.get('line_start'))
    if type(start) is not int or type(end) is not int or not 1 <= start <= end <= len(original):
        return {**result, 'reason': 'invalid_replacement_anchor'}
    snippet = str(finding.get('code_snippet') or '').splitlines()
    if [line.strip() for line in original[start - 1:end]] != [line.strip() for line in snippet]:
        return {**result, 'reason': 'replacement_anchor_does_not_match_source'}
    # Match the production normalizer's indentation restoration, without its
    # truncation: truncated proposals must fail rather than silently change code.
    indent = original[start - 1][:len(original[start - 1]) - len(original[start - 1].lstrip())]
    meaningful = [line for line in replacement if line.strip()]
    if meaningful:
        current = min(len(line) - len(line.lstrip()) for line in meaningful)
        if current < len(indent):
            replacement = [indent[current:] + line if line.strip() else line for line in replacement]
    patched = '\n'.join(original[:start - 1] + replacement + original[end:]) + '\n'
    result['application_checked'] = True
    suffix = Path(str(finding.get('file_path', ''))).suffix.lower()
    if suffix == '.py':
        try:
            ast.parse(patched)
        except (SyntaxError, ValueError, TypeError, RecursionError):
            return {**result, 'syntax_checked': True, 'reason': 'replacement_does_not_parse'}
    elif suffix in {'.js', '.cjs', '.mjs'}:
        executable = shutil.which('node')
        if not executable:
            return {**result, 'reason': 'syntax_checker_unavailable'}
        try:
            check = subprocess.run([executable, '--check', '--input-type=module' if suffix == '.mjs' else '--input-type=commonjs'],
                                   input=patched, text=True, capture_output=True, timeout=5,
                                   env={'PATH': os.defpath})
        except (OSError, subprocess.TimeoutExpired):
            return {**result, 'reason': 'syntax_checker_failed'}
        if check.returncode:
            return {**result, 'syntax_checked': True, 'reason': 'replacement_does_not_parse'}
    else:
        return {**result, 'reason': 'replacement_language_not_supported'}
    return {**result, 'status': 'syntax_only_passed', 'syntax_checked': True,
            'reason': 'syntax_is_not_proof_of_security_or_behavior'}


def summarize(rows):
    live = [r for r in rows if r['mode'] == 'live']
    metrics = {}
    for name in sorted({k for r in live for k in r.get('scores', {})}):
        values = [r['scores'][name] for r in live if name in r.get('scores', {})]
        metrics[name] = {'passed': sum(values), 'total': len(values)}
    groups = {}
    for row in live:
        groups.setdefault(row['case_id'], []).append(row)
    stability = [len({r['observed_verdict'] for r in group}) == 1 and
                 all(r['observed_verdict'] is not None for r in group)
                 for group in groups.values() if len(group) > 1]
    durations = sorted(r['elapsed_ms'] for r in live)
    faults = [r for r in rows if r['mode'] != 'live']
    replacement_results = [r.get('replacement_validation', {}) for r in live]
    return {'live_cases': len(live), 'metrics': metrics,
            'replacement_code': {
                'not_proposed': sum(item.get('status') == 'not_proposed' for item in replacement_results),
                'syntax_only_passed': sum(item.get('status') == 'syntax_only_passed' for item in replacement_results),
                'rejected': sum(item.get('status') == 'rejected' for item in replacement_results),
                'sandbox_verified_repairs': 0, 'semantic_correctness': 'not_evaluated'},
            'verdict_stability': {'passed': sum(stability), 'total': len(stability)},
            'latency_p50_ms': statistics.median(durations) if durations else None,
            'latency_p95_ms': durations[max(0, math.ceil(len(durations) * .95) - 1)] if durations else None,
            'estimated_known_cost_usd': sum(r.get('estimated_cost_usd', 0) for r in live),
            'unknown_cost_cases': sum(r.get('cost_unknown', False) for r in live),
            'fault_recovery': {'passed': sum(
                r.get('fault_exercised', False) and r.get('fallback_preserved', False) for r in faults),
                               'total': len(faults)}}


def report_validation_errors(report, cases_path=HERE/'cases.json'):
    """Reject incomplete, stale, or internally inconsistent smoke evidence.

    This verifies reproducibility and scope, not authenticity or independent human review.
    In particular, a locally editable report can never authorize production publication.
    """
    try:
        if type(report.get('schema_version')) is not int or report['schema_version'] != REPORT_SCHEMA_VERSION:
            return ['unsupported_or_legacy_report_schema']
        suite = json.loads(cases_path.read_text())['cases']
        ids = report['case_ids']
        if (not isinstance(ids, list) or not ids or any(not isinstance(item, str) for item in ids)
                or len(ids) != len(set(ids))):
            return ['invalid_case_selection']
        cases = [case for case in suite if case['id'] in ids]
        if [case['id'] for case in cases] != ids:
            return ['fixture_case_selection_mismatch']
        plan = request_plan(cases, report['repeats'], report['faults_only'])
        if report['planned_requests'] != plan:
            return ['request_plan_mismatch']
        expected_live = sum(item['mode'] == 'live' for item in plan)
        if type(report['planned_live_requests']) is not int or report['planned_live_requests'] != expected_live:
            return ['planned_live_request_count_mismatch']
        expected_kind = 'fault_recovery_smoke' if report['faults_only'] else 'live_recommendation_smoke'
        if report['results_kind'] != expected_kind:
            return ['report_scope_mismatch']
        errors = [key + '_mismatch' for key, value in source_bindings(cases).items() if report.get(key) != value]
        if errors:
            return errors
        rows = report['rows']
        if not isinstance(rows, list) or any(not isinstance(row, dict) for row in rows):
            return ['invalid_report_rows']
        identities = [(row['mode'], row['case_id'], row['repeat']) for row in rows]
        expected = {(item['mode'], item['case_id'], item['repeat']) for item in plan}
        if (any(type(row['repeat']) is not int for row in rows)
                or len(identities) != len(set(identities)) or set(identities) != expected):
            return ['planned_rows_missing_duplicate_or_unexpected']
        cases_by_id = {case['id']: case for case in cases}
        for row in rows:
            case = cases_by_id[row['case_id']]
            if row.get('pipeline_completed') is not True or row.get('http_status') != 200:
                return ['incomplete_pipeline']
            if (type(row.get('elapsed_ms')) not in (int, float) or not math.isfinite(row['elapsed_ms'])
                    or row['elapsed_ms'] < 0 or type(row.get('provider_calls')) is not int
                    or row['provider_calls'] != 1):
                return ['invalid_observation_counts']
            if row.get('expected_verdict') != case['expected_verdict']:
                return ['expected_verdict_mismatch']
            verdict, advice, expected_scores = score(case, row['response'], row)
            if 'transported_recommendation' not in row:
                return ['transport_evidence_missing']
            expected_scores['recommendation_transport'] = int(row['transported_recommendation'] == advice)
            scores = row.get('scores')
            if (not isinstance(scores, dict) or set(scores) != set(expected_scores)
                    or any(type(value) is not int or value not in (0, 1) for value in scores.values())
                    or scores != expected_scores or row.get('observed_verdict') != verdict):
                return ['mandatory_metrics_missing_or_inconsistent']
            replacement = row.get('replacement_validation')
            if (not isinstance(replacement, dict)
                    or digest(replacement) != digest(replacement_validation(case, row))):
                return ['replacement_validation_missing_or_inconsistent']
            if row['mode'] != 'live' and (row.get('injected_fault') != row['mode']
                    or row.get('fault_exercised') is not True or row.get('fallback_preserved') is not True):
                return ['unexercised_fault_or_missing_fallback']
        if digest(report['summary']) != digest(summarize(rows)):
            return ['summary_does_not_match_rows']
        return []
    except (OSError, ValueError, KeyError, TypeError, AttributeError, StopIteration, RecursionError, SyntaxError):
        return ['invalid_or_incomplete_report']


def report_passed(report, cases_path=HERE/'cases.json'):
    """Complete, current smoke agreement only; never a production accuracy claim."""
    if report_validation_errors(report, cases_path):
        return False
    return all(row['replacement_validation']['status'] != 'rejected'
               and all(value == 1 for key, value in row['scores'].items() if key != 'fix_terms_heuristic')
               for row in report['rows'] if row['mode'] == 'live')


def verify_saved_report(report, cases_path=HERE/'cases.json'):
    errors = report_validation_errors(report, cases_path)
    if errors:
        raise ValueError('saved_report_refused:' + ','.join(errors))
    expected = 'passed' if report_passed(report, cases_path) else 'failed'
    if report.get('evaluation_status') != expected:
        raise ValueError('saved_report_status_mismatch')


@contextmanager
def local_server(app):
    import uvicorn
    sock = socket.socket()
    sock.bind(('127.0.0.1', 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level='critical', access_log=False))
    worker = threading.Thread(target=server.run, kwargs={'sockets': [sock]}, daemon=True)
    worker.start()
    try:
        deadline = time.monotonic() + 10
        while not server.started:
            if not worker.is_alive() or time.monotonic() > deadline:
                raise RuntimeError('local_server_start_failed')
            time.sleep(.02)
        yield f'http://127.0.0.1:{port}'
    finally:
        server.should_exit = True
        worker.join(timeout=5)
        sock.close()


def run_live(args):
    import httpx
    import openai
    sys.path.insert(0, str(ROOT / 'services/analysis-service/src'))
    import llm_triage as triage
    import main as analysis_main
    from main import app
    from analysis_grpc_server import _parse_analysis_response, _message_to_dict, analysis_pb2

    suite = json.loads(args.cases.read_text())
    cases = suite['cases']
    if args.case:
        if not set(args.case).issubset({case['id'] for case in cases}):
            raise ValueError('unknown_selected_case')
        cases = [c for c in cases if c['id'] in args.case]
    if not cases or len(cases) * args.repeats > 12:
        raise ValueError('select_between_1_and_12_live_requests')
    key = os.environ.get(args.api_key_env)
    if not key and not args.faults_only:
        raise ValueError('provider_key_missing')
    secret = uuid.uuid4().hex
    values = {'LLM_PROVIDER': 'openai_compatible', 'LLM_MODEL': args.model,
              'LLM_API_KEY': key or 'local-fault-injection', 'LLM_BASE_URL': args.base_url, 'LLM_TRIAGE_ENABLED': 'true',
              'ANALYSIS_SERVICE_INTERNAL_SECRET': secret, 'OTEL_SDK_DISABLED': 'true',
              'LANGSMITH_TRACING': 'false', 'LANGCHAIN_TRACING': 'false', 'LANGCHAIN_TRACING_V2': 'false'}
    plan = request_plan(cases, args.repeats, args.faults_only)
    report = {'schema_version': REPORT_SCHEMA_VERSION, 'evaluation_status': 'in_progress',
              'model': args.model, 'results_kind': 'fault_recovery_smoke' if args.faults_only else 'live_recommendation_smoke',
              **source_bindings(cases), 'case_ids': [case['id'] for case in cases],
              'repeats': args.repeats, 'faults_only': args.faults_only, 'planned_requests': plan,
              'scope': 'local HTTP Tier 3 -> real model -> validation -> response -> gRPC serialization',
              'limitations': ['Curated synthetic cases, not production precision/recall.',
                             'Citation checks and keyword heuristics do not prove fix correctness.',
                             'Fault injection is separate from live model runs.',
                             'Optional replacement code is applied to the synthetic file and syntax-checked only.',
                             'No GitHub, database, frontend or repair execution exercised.'],
              'replacement_validation_scope': 'application_and_syntax_only',
              'sandbox_verified_repairs': 0,
              'prices_per_million': {'input': args.input_price, 'output': args.output_price},
              'max_cost_usd': args.max_cost, 'planned_live_requests': 0 if args.faults_only else len(cases)*args.repeats,
              'rows': [], 'upload': {'status': 'disabled'}}
    spent_or_reserved = 0.0
    original_provider = triage.call_llm
    original_constructor = openai.OpenAI
    current = {}
    mode = 'live'

    def observed_provider(**kwargs):
        nonlocal spent_or_reserved
        started, clock = now(), time.perf_counter()
        # Deliberately generous input estimate. This is an estimated reservation, not a billing cap.
        estimate_in = 2 * len((kwargs['system_prompt'] + kwargs['user_prompt']).encode()) + 1024
        reservation = (estimate_in * args.input_price + kwargs['max_output_tokens'] * args.output_price) / 1e6
        if mode == 'live' and spent_or_reserved + reservation > args.max_cost:
            current['budget_exhausted'] = True
            raise RuntimeError('evaluation_budget_exhausted')
        current['provider_calls'] = current.get('provider_calls', 0) + 1
        stage = {'name': 'model', 'started_at': started, 'mode': mode}
        try:
            if mode == 'timeout':
                current['injected_fault'] = 'timeout'
                raise TimeoutError('injected_timeout')
            if mode == 'malformed':
                from llm_client import LLMResponse
                current['injected_fault'] = 'malformed'
                return LLMResponse('not json', 0, 0, 'fault_injection', args.model)
            # Keep synthetic prompt/response locally for human review, never upload them.
            current['prompt'] = kwargs['user_prompt']
            response = original_provider(**kwargs)
            current['raw_response'] = response.text
            current['usage'] = {'input_tokens': response.input_tokens, 'output_tokens': response.output_tokens}
            if response.input_tokens <= 0:
                current['cost_unknown'] = True
                spent_or_reserved += reservation
            else:
                cost = (response.input_tokens * args.input_price + response.output_tokens * args.output_price) / 1e6
                current['estimated_cost_usd'] = cost
                spent_or_reserved += cost
            return response
        except Exception as error:
            stage['error_type'] = type(error).__name__
            if mode == 'live':
                current['cost_unknown'] = True
                spent_or_reserved += reservation
                current['provider_error'] = type(error).__name__
                current['provider_http_status'] = getattr(error, 'status_code', None)
            raise
        finally:
            stage.update(ended_at=now(), elapsed_ms=round((time.perf_counter()-clock)*1000, 2))
            current.setdefault('stages', []).append(stage)

    def instrument(name, original):
        def wrapped(*a, **kw):
            started, clock = now(), time.perf_counter()
            stage = {'name': name, 'started_at': started}
            try:
                result = original(*a, **kw)
                if name == 'parse':
                    current['raw_model_verdicts'] = result
                elif name == 'safety_override':
                    # Release scoring must reflect the verdict that the API actually
                    # applies, while preserving the raw model output for diagnosis.
                    current['verdicts'] = result
                return result
            except Exception as error:
                stage['error_type'] = type(error).__name__
                raise
            finally:
                stage.update(ended_at=now(), elapsed_ms=round((time.perf_counter()-clock)*1000, 2))
                current.setdefault('stages', []).append(stage)
        return wrapped

    def no_retry_client(**kw):
        return original_constructor(**kw, max_retries=0)

    # Production admits only exact rule definitions bound to checked-in release
    # evidence. These synthetic IDs are intentionally absent from that allowlist.
    # Admit them only while the isolated evaluator is running; never edit or bypass
    # the packaged production policy to make a benchmark pass.
    evaluation_rule_ids = benchmark_rule_ids(cases)
    cases_by_id = {case['id']: case for case in cases}
    jobs = [(cases_by_id[item['case_id']], item['mode'], item['repeat']) for item in plan]
    provider_broken = False
    with environment(values), \
         patch.object(analysis_main, 'PUBLICATION_RULE_IDS',
                      analysis_main.PUBLICATION_RULE_IDS | evaluation_rule_ids), \
         patch.object(openai, 'OpenAI', no_retry_client), \
         patch.object(triage, 'call_llm', observed_provider), \
         patch.object(triage, '_build_triage_prompt', instrument('context', triage._build_triage_prompt)), \
         patch.object(triage, '_parse_triage_response', instrument('parse', triage._parse_triage_response)), \
         patch.object(triage, '_apply_deterministic_safety_overrides', instrument(
             'safety_override', triage._apply_deterministic_safety_overrides)), \
         patch.object(triage, '_apply_verdicts', instrument('validate_enrich', triage._apply_verdicts)), \
         local_server(app) as base, httpx.Client(timeout=65, trust_env=False) as client:
        for case, mode, repeat in jobs:
            if mode == 'live' and provider_broken:
                continue
            current = {'case_id': case['id'], 'expected_verdict': case['expected_verdict'],
                       'mode': mode, 'repeat': repeat, 'started_at': now(), 'provider_calls': 0}
            current['scores'] = score(case, {}, current)[2]
            payload = {'repository_full_name': 'local/synthetic-evaluation', 'pull_request_number': 1,
                       'commit_sha': 'a'*40, 'findings': [case['finding']],
                       'file_patches': {case['finding']['file_path']: case['file_patch']},
                       'repo_profile': case.get('repo_profile', {})}
            clock = time.perf_counter()
            try:
                with redirect_stdout(io.StringIO()):
                    response = client.post(base+'/analyze/pr/tier3', json=payload,
                                           headers={'x-internal-secret': secret})
                current['http_status'] = response.status_code
                response.raise_for_status()
                body = response.json()
                current['response'] = body
                verdict, advice, scores = score(case, body, current)
                current.update(observed_verdict=verdict, scores=scores)
                current['replacement_validation'] = replacement_validation(case, current)
                transport_start, transport_clock = now(), time.perf_counter()
                decoded = _message_to_dict(analysis_pb2.AnalyzePullRequestResponse.FromString(
                    _parse_analysis_response(body).SerializeToString()))
                wired_advice = next((f.get('evidence_details', {}).get('extra', {}).get('llm_recommendation')
                                    for f in decoded.get('findings', [])), None)
                current['transported_recommendation'] = wired_advice
                scores['recommendation_transport'] = int(wired_advice == advice)
                current.setdefault('stages', []).append({'name': 'transport', 'started_at': transport_start,
                    'ended_at': now(), 'elapsed_ms': round((time.perf_counter()-transport_clock)*1000, 2)})
                if mode != 'live':
                    current['fallback_preserved'] = any(
                        f.get('fingerprint') == case['finding']['fingerprint'] and
                        f.get('remediation') == case['finding'].get('remediation') and
                        not f.get('llm_triage') for f in body.get('findings', []))
                current['pipeline_completed'] = True
            except Exception as error:
                current.update(error_type=type(error).__name__, observed_verdict=None)
            if mode != 'live':
                current['fault_exercised'] = (
                    current.get('injected_fault') == mode and current.get('provider_calls') == 1)
            current.update(ended_at=now(), elapsed_ms=round((time.perf_counter()-clock)*1000, 2))
            report['rows'].append(current)
            report['summary'] = summarize(report['rows'])
            report['spent_or_reserved_usd'] = spent_or_reserved
            save(args.output, report)
            print(json.dumps({k: current.get(k) for k in ['case_id','mode','repeat','http_status','observed_verdict',
                             'scores','elapsed_ms','estimated_cost_usd','provider_error','provider_http_status']}), flush=True)
            if mode == 'live' and (current.get('provider_error') or current.get('budget_exhausted')):
                provider_broken = True  # Still exercise the independent, unbilled fault checks.
    passed = report_passed(report, args.cases)
    report['evaluation_status'] = 'passed' if passed else 'failed'
    save(args.output, report)
    print(json.dumps({'evaluation_status': report['evaluation_status'], **report['summary']}, indent=2))
    return 0 if passed else 1


def upload_saved(args, client=None):
    report = json.loads(args.upload_only.read_text())
    # Validate before constructing an external client or modifying the saved report. Failed
    # but complete/current experiments remain useful observations; stale/incomplete ones do not.
    verify_saved_report(report, getattr(args, 'cases', HERE/'cases.json'))
    rows = report['rows']
    if not 1 <= len(rows) <= 14:
        raise ValueError('upload_case_limit')
    if client is None:
        from langsmith import Client
        client = Client(auto_batch_tracing=False)
    dataset_name = 'mitig8it-recommendations-' + report['fixture_digest'][:12]
    dataset = (client.read_dataset(dataset_name=dataset_name) if client.has_dataset(dataset_name=dataset_name)
               else client.create_dataset(dataset_name=dataset_name, description='Synthetic case IDs and expected verdicts only.'))
    examples = {e.inputs['case_id']: e for e in client.list_examples(dataset_id=dataset.id)}
    project_name = 'mitig8it-recommendations-' + uuid.uuid4().hex[:12]
    project = client.create_project(project_name=project_name, reference_dataset_id=dataset.id,
                                   metadata={'model': report['model'], 'prompt_digest': report['prompt_digest'],
                                             'source_digest': report.get('source_digest'),
                                             'results_kind': report['results_kind']})
    report['upload'] = {'status': 'in_progress', 'experiment_id': str(project.id),
                        'experiment_name': project_name, 'dataset_id': str(dataset.id)}
    save(args.upload_only, report)
    run_ids = []
    for row in rows:
        example = examples.get(row['case_id'])
        if example is None:
            example = client.create_example(dataset_id=dataset.id, inputs={'case_id':row['case_id']},
                                            outputs={'expected_verdict':row['expected_verdict']})
            examples[row['case_id']] = example
        run_id = uuid.uuid4()
        run_ids.append(str(run_id))
        start = datetime.fromisoformat(row['started_at'])
        order = start.strftime('%Y%m%dT%H%M%S%fZ') + str(run_id)
        # Explicit allowlist: raw prompts, model outputs and code never leave this local report.
        outputs = {k:row[k] for k in ['observed_verdict','elapsed_ms','estimated_cost_usd','cost_unknown',
                                      'provider_calls','http_status','fallback_preserved'] if k in row}
        client.create_run(id=run_id, name='recommendation-http-evaluation', run_type='chain',
                          project_name=project_name, reference_example_id=example.id,
                          trace_id=run_id, dotted_order=order,
                          start_time=start, end_time=datetime.fromisoformat(row['ended_at']),
                          inputs={'case_id':row['case_id'],'mode':row['mode'],'repeat':row['repeat']}, outputs=outputs)
        for stage in row.get('stages', []):
            stage_id = uuid.uuid4()
            stage_start = datetime.fromisoformat(stage['started_at'])
            extra = {'metadata': {'ls_model_name':report['model'],'mode':row['mode']}}
            stage_outputs = {k:stage[k] for k in ['elapsed_ms','error_type'] if k in stage}
            if stage['name'] == 'model':
                stage_outputs.update(row.get('usage', {}))
                if 'estimated_cost_usd' in row:
                    stage_outputs['estimated_cost_usd'] = row['estimated_cost_usd']
                    usage = dict(row['usage'])
                    usage['total_tokens'] = usage['input_tokens'] + usage['output_tokens']
                    usage['total_cost'] = row['estimated_cost_usd']
                    extra['metadata']['usage_metadata'] = usage
            client.create_run(id=stage_id, name=stage['name'], run_type='llm' if stage['name']=='model' else 'chain',
                              project_name=project_name, parent_run_id=run_id, trace_id=run_id,
                              dotted_order=order+'.'+stage_start.strftime('%Y%m%dT%H%M%S%fZ')+str(stage_id),
                              start_time=stage_start, end_time=datetime.fromisoformat(stage['ended_at']),
                              inputs={'case_id':row['case_id']}, outputs=stage_outputs, extra=extra)
        for key, value in row.get('scores', {}).items():
            if row['mode'] != 'live':
                continue
            client.create_feedback(run_id=run_id, key=key, score=value, session_id=project.id,
                                   start_time=start, extend_trace_retention=False)
        if row['mode'] != 'live':
            client.create_feedback(run_id=run_id, key='fallback_preserved', score=int(row.get('fallback_preserved',False)),
                                   session_id=project.id, start_time=start, extend_trace_retention=False)
    client.update_project(project.id, end_time=datetime.now(timezone.utc))
    # Read back one root trace to verify ingestion, rather than just trusting the write return.
    client.read_run(run_ids[0])
    report['upload'] = {'status':'uploaded','experiment_id':str(project.id),'experiment_name':project_name,
                        'dataset_id':str(dataset.id),'root_runs':len(rows),'first_run_id':run_ids[0]}
    save(args.upload_only, report)
    print(json.dumps(report['upload'], indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--cases', type=Path, default=HERE/'cases.json')
    parser.add_argument('--case', action='append')
    parser.add_argument('--output', type=Path, default=ROOT/'benchmarks/results/recommendations-live.json')
    parser.add_argument('--model')
    parser.add_argument('--base-url', default='https://api.anthropic.com/v1')
    parser.add_argument('--api-key-env', default='ANTHROPIC_API_KEY')
    parser.add_argument('--input-price', type=float)
    parser.add_argument('--output-price', type=float)
    parser.add_argument('--max-cost', type=float, default=1.0)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--upload-only', type=Path)
    parser.add_argument('--verify-only', type=Path, help='Validate a saved smoke report offline; never authorize production publication')
    parser.add_argument('--faults-only', action='store_true', help='Exercise timeout/malformed fallback without any provider request')
    parser.add_argument('--env-file', type=Path, help='Explicit opt-in to loading the existing development key allowlist')
    args = parser.parse_args()
    if args.env_file:
        sys.path.insert(0, str(ROOT))
        from benchmarks.remediation.dev_eval import local_env_file
        with local_env_file(args.env_file):
            args.env_file = None
            return execute(args, parser)
    return execute(args, parser)


def execute(args, parser):
    if args.verify_only:
        if args.upload_only:
            parser.error('--verify-only and --upload-only are mutually exclusive')
        try:
            report = json.loads(args.verify_only.read_text())
            verify_saved_report(report, args.cases)
        except (OSError, ValueError, TypeError) as error:
            print(json.dumps({'saved_report_valid': False, 'reason': str(error) if isinstance(error, ValueError) else type(error).__name__}))
            return 1
        passed = report['evaluation_status'] == 'passed'
        print(json.dumps({'saved_report_valid': True, 'smoke_passed': passed,
                          'scope': 'local_smoke_only', 'production_ready': False}))
        return 0 if passed else 1
    if args.upload_only:
        try:
            upload_saved(args)
            return 0
        except Exception as error:
            report = json.loads(args.upload_only.read_text())
            report['upload'] = {**report.get('upload', {}), 'status': 'failed', 'error_type': type(error).__name__}
            save(args.upload_only, report)
            print(json.dumps({'upload':'failed','error_type':type(error).__name__}))
            return 1
    if not args.model or not args.base_url.startswith('https://') or args.repeats not in (1,2):
        parser.error('provide --model, an HTTPS provider URL, and --repeats 1 or 2')
    if any(v is None or not math.isfinite(v) or v <= 0 for v in [args.input_price,args.output_price,args.max_cost]):
        parser.error('positive model prices and budget are required')
    return run_live(args)


if __name__ == '__main__':
    raise SystemExit(main())
