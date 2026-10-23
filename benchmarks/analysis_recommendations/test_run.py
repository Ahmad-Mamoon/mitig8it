import argparse
import copy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

spec = importlib.util.spec_from_file_location('recommendation_eval', Path(__file__).with_name('run.py'))
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


def complete_report(case_id='authorization_helper_missing_context', repeats=1, faults_only=False):
    """Fully observed synthetic evidence, never a real model or independent review."""
    case = next(case for case in json.loads((evaluation.HERE/'cases.json').read_text())['cases'] if case['id'] == case_id)
    plan = evaluation.request_plan([case], repeats, faults_only)
    timestamp = '2026-10-05T12:00:00+00:00'
    rows = []
    for item in plan:
        live = item['mode'] == 'live'
        row = {**item, 'expected_verdict': case['expected_verdict'], 'provider_calls': 1,
               'pipeline_completed': True, 'http_status': 200, 'elapsed_ms': 10,
               'started_at': timestamp, 'ended_at': timestamp,
               'verdicts': [{'fingerprint': case['finding']['fingerprint'], 'verdict': case['expected_verdict']}] if live else [],
               'response': {'findings': [copy.deepcopy(case['finding'])]}}
        row['raw_model_verdicts'] = copy.deepcopy(row['verdicts'])
        if live and case['expected_verdict'] == 'true_positive':
            row['response']['findings'][0]['evidence_details'].setdefault('extra', {})['llm_recommendation'] = {'fix': 'repo-specific advice'}
        verdict, advice, scores = evaluation.score(case, row['response'], row)
        row.update(observed_verdict=verdict, scores=scores, transported_recommendation=advice)
        row['scores']['recommendation_transport'] = 1
        row['replacement_validation'] = evaluation.replacement_validation(case, row)
        if not live:
            row.update(injected_fault=item['mode'], fault_exercised=True, fallback_preserved=True)
        rows.append(row)
    return {'schema_version': evaluation.REPORT_SCHEMA_VERSION, 'model': 'test-model',
            'evaluation_status': 'passed', 'case_ids': [case_id], 'repeats': repeats, 'faults_only': faults_only,
            'planned_requests': plan, 'planned_live_requests': 0 if faults_only else repeats,
            'results_kind': 'fault_recovery_smoke' if faults_only else 'live_recommendation_smoke',
            **evaluation.source_bindings([case]), 'rows': rows, 'summary': evaluation.summarize(rows)}


def test_benchmark_rule_ids_are_derived_from_fixtures_without_empty_values():
    cases = [
        {'finding': {'rule_id': 'synthetic.sql'}},
        {'finding': {'rule_id': 'synthetic.sql'}},
        {'finding': {'rule_id': 'synthetic.shell'}},
        {'finding': {}},
    ]
    assert evaluation.benchmark_rule_ids(cases) == frozenset({'synthetic.sql', 'synthetic.shell'})


def test_fallback_is_not_scored_as_model_success():
    case = {'finding': {'fingerprint': 'f'}, 'expected_verdict': 'uncertain'}
    verdict, advice, scores = evaluation.score(case, {'findings':[case['finding']]}, {'provider_calls':1})
    assert verdict is None
    assert scores['verdict_match'] == scores['parsed_verdict'] == 0


def test_safe_removal_requires_observed_verdict():
    case = {'finding': {'fingerprint': 'f'}, 'expected_verdict': 'false_positive'}
    _, _, scores = evaluation.score(case, {'findings':[]}, {'provider_calls':1})
    assert scores['verdict_match'] == 0
    _, _, scores = evaluation.score(case, {'findings':[]}, {
        'provider_calls':1, 'verdicts':[{'fingerprint':'f','verdict':'false_positive'}]})
    assert scores['verdict_match'] == 1


def replacement_case(source='value = unsafe(user)', suffix='.py'):
    return {'finding': {'fingerprint': 'f', 'file_path': 'app' + suffix,
                        'line_start': 1, 'line_end': 1, 'code_snippet': source},
            'file_patch': '@@ -0,0 +1 @@\n+' + source}


def replacement_observation(code):
    return {'raw_model_verdicts': [{'fingerprint': 'f', 'fixed_code': code}]}


def test_advisory_prose_is_not_scored_as_a_verified_repair():
    result = evaluation.replacement_validation(replacement_case(), {
        'raw_model_verdicts': [{'fingerprint': 'f', 'remediation': 'Validate input'}]})
    assert result['status'] == 'not_proposed'
    assert not any(result[key] for key in (
        'application_checked', 'syntax_checked', 'behavior_checked',
        'sandbox_verified', 'ready_for_inline_publication'))


def test_valid_python_with_unknown_helper_passes_syntax_only_never_behavior():
    result = evaluation.replacement_validation(
        replacement_case(), replacement_observation('value = undefined_helper(user)'))
    assert result['status'] == 'syntax_only_passed'
    assert result['application_checked'] is result['syntax_checked'] is True
    assert result['behavior_checked'] is result['sandbox_verified'] is False
    assert result['ready_for_inline_publication'] is False


def test_python_replacement_must_parse_in_full_source():
    result = evaluation.replacement_validation(
        replacement_case(), replacement_observation('value = ('))
    assert result['status'] == 'rejected'
    assert result['reason'] == 'replacement_does_not_parse'


def test_replacement_rejects_stale_or_partial_diff_anchor():
    case = replacement_case()
    case['finding']['code_snippet'] = 'unrelated()'
    assert evaluation.replacement_validation(case, replacement_observation('value = 1'))['reason'] == 'replacement_anchor_does_not_match_source'
    case = replacement_case()
    case['file_patch'] = '@@ -1 +1 @@\n-old()\n+value = unsafe(user)'
    assert evaluation.replacement_validation(case, replacement_observation('value = 1'))['reason'] == 'complete_added_file_required'


def test_javascript_checker_only_parses_and_never_executes_proposal():
    if not evaluation.shutil.which('node'):
        import pytest
        pytest.skip('node is not installed')
    case = replacement_case('const value = unsafe(user);', '.js')
    # Executing this would fail; --check must only parse it.
    valid = evaluation.replacement_validation(case, replacement_observation('throw new Error("must not execute");'))
    assert valid['status'] == 'syntax_only_passed'
    invalid = evaluation.replacement_validation(case, replacement_observation('const value = ;'))
    assert invalid['reason'] == 'replacement_does_not_parse'


def test_duplicate_verdicts_use_last_like_production_and_fail_ambiguity_gate():
    case = {'finding': {'fingerprint': 'f'}, 'expected_verdict': 'uncertain'}
    verdict, _, scores = evaluation.score(case, {}, {'provider_calls': 1, 'verdicts': [
        {'fingerprint': 'f', 'verdict': 'true_positive'},
        {'fingerprint': 'f', 'verdict': 'uncertain'}]})
    assert verdict == 'uncertain'
    assert scores['unambiguous_verdict'] == 0


def test_invalid_replacement_fails_report_even_when_verdict_scores_pass():
    report = complete_report()
    row = report['rows'][0]
    row['raw_model_verdicts'][0]['fixed_code'] = 'return ('
    case = next(case for case in json.loads((evaluation.HERE/'cases.json').read_text())['cases'] if case['id'] == row['case_id'])
    row['replacement_validation'] = evaluation.replacement_validation(case, row)
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_validation_errors(report) == []
    assert evaluation.report_passed(report) is False
    assert report['summary']['replacement_code']['rejected'] == 1
    assert report['summary']['replacement_code']['sandbox_verified_repairs'] == 0


def test_stability_ignores_faults_and_does_not_count_repeated_failure_as_stable():
    rows = [{'mode':'live','case_id':'a','observed_verdict':None,'elapsed_ms':10,'scores':{}},
            {'mode':'live','case_id':'a','observed_verdict':None,'elapsed_ms':20,'scores':{}},
            {'mode':'timeout','case_id':'a','fault_exercised':True,'fallback_preserved':True}]
    result = evaluation.summarize(rows)
    assert result['verdict_stability'] == {'passed':0,'total':1}
    assert result['fault_recovery'] == {'passed':1,'total':1}
    assert result['latency_p50_ms'] == 15


def test_fault_recovery_requires_the_injected_provider_path_to_run():
    rows = [{'mode':'timeout','case_id':'a','fallback_preserved':True,
             'fault_exercised':False}]
    assert evaluation.summarize(rows)['fault_recovery'] == {'passed':0,'total':1}


def test_report_cannot_pass_an_incomplete_pipeline_or_unexercised_fault():
    report = complete_report()
    live, fault = report['rows'][:2]
    live['pipeline_completed'] = False
    assert evaluation.report_passed(report) is False

    live['pipeline_completed'] = True
    fault['fault_exercised'] = False
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_passed(report) is False

    fault['fault_exercised'] = True
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_passed(report) is True


def test_complete_current_report_has_verifiable_plan_summary_and_bindings():
    report = complete_report()
    assert evaluation.report_validation_errors(report) == []
    assert evaluation.report_passed(report)
    evaluation.verify_saved_report(report)


@pytest.mark.parametrize('metric', ['verdict_match', 'parsed_verdict', 'unambiguous_verdict',
                                    'one_model_call', 'recommendation_transport'])
def test_every_completed_row_requires_each_metric(metric):
    report = complete_report()
    del report['rows'][0]['scores'][metric]
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_validation_errors(report) == ['mandatory_metrics_missing_or_inconsistent']
    assert not evaluation.report_passed(report)


@pytest.mark.parametrize('metric', ['grounded_recommendation', 'fix_terms_heuristic'])
def test_positive_cases_require_advisory_metrics_but_keywords_remain_auxiliary(metric):
    report = complete_report('sql_interpolation')
    assert report['rows'][0]['scores']['fix_terms_heuristic'] == 0
    assert evaluation.report_passed(report), 'keyword matching must not become semantic proof'
    del report['rows'][0]['scores'][metric]
    report['summary'] = evaluation.summarize(report['rows'])
    assert not evaluation.report_passed(report)


@pytest.mark.parametrize('missing', ['replacement_validation', 'transported_recommendation', 'response'])
def test_missing_completed_row_evidence_fails_closed(missing):
    report = complete_report()
    del report['rows'][0][missing]
    assert not evaluation.report_passed(report)


def test_empty_metrics_no_longer_pass_vacuously():
    report = complete_report()
    report['rows'][0]['scores'] = {}
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_validation_errors(report) == ['mandatory_metrics_missing_or_inconsistent']


@pytest.mark.parametrize('mutation', ['duplicate', 'missing', 'unexpected_case', 'unexpected_repeat', 'boolean_repeat'])
def test_exact_unique_planned_case_repeat_coverage_is_required(mutation):
    report = complete_report(repeats=2)
    if mutation == 'duplicate':
        report['rows'][1] = copy.deepcopy(report['rows'][0])  # Same count, but repeat 2 disappeared.
    elif mutation == 'missing':
        report['rows'].pop()
    elif mutation == 'unexpected_case':
        report['rows'][0]['case_id'] = 'unplanned-case'
    elif mutation == 'unexpected_repeat':
        report['rows'][0]['repeat'] = 3
    else:
        report['rows'][0]['repeat'] = True
    assert evaluation.report_validation_errors(report) == ['planned_rows_missing_duplicate_or_unexpected']


def test_plan_cannot_be_changed_to_hide_a_missing_case_or_fault():
    report = complete_report()
    report['planned_requests'].pop()
    report['rows'].pop()
    report['summary'] = evaluation.summarize(report['rows'])
    assert evaluation.report_validation_errors(report) == ['request_plan_mismatch']


@pytest.mark.parametrize('binding', ['source_digest', 'prompt_digest', 'fixture_digest', 'evaluator_digest'])
def test_saved_report_rejects_stale_or_tampered_input_binding(binding):
    report = complete_report()
    report[binding] = '0' * 64
    with pytest.raises(ValueError, match=binding + '_mismatch'):
        evaluation.verify_saved_report(report)


def test_saved_summary_is_recomputed_instead_of_trusted():
    report = complete_report()
    report['summary']['metrics']['verdict_match']['passed'] = 100
    assert evaluation.report_validation_errors(report) == ['summary_does_not_match_rows']
    with pytest.raises(ValueError, match='summary_does_not_match_rows'):
        evaluation.verify_saved_report(report)


@pytest.mark.parametrize('mutation', ['boolean_flag', 'nan_latency'])
def test_non_boolean_scope_flags_and_non_finite_measurements_fail_closed(mutation):
    report = complete_report()
    if mutation == 'boolean_flag':
        report['rows'][0]['replacement_validation']['behavior_checked'] = 0
    else:
        report['rows'][0]['elapsed_ms'] = float('nan')
    assert not evaluation.report_passed(report)


def test_scores_cannot_disagree_with_observed_verdict_and_response():
    report = complete_report()
    report['rows'][0]['verdicts'][0]['verdict'] = 'true_positive'
    assert evaluation.report_validation_errors(report) == ['mandatory_metrics_missing_or_inconsistent']


def test_reported_not_proposed_cannot_hide_an_invalid_raw_replacement():
    report = complete_report()
    report['rows'][0]['raw_model_verdicts'][0]['fixed_code'] = 'return ('
    assert evaluation.report_validation_errors(report) == ['replacement_validation_missing_or_inconsistent']


def test_fault_only_reports_are_explicitly_scoped_and_need_both_exercised_faults():
    report = complete_report(faults_only=True)
    assert evaluation.report_passed(report)
    assert report['results_kind'] == 'fault_recovery_smoke'
    assert report['planned_live_requests'] == 0
    report['rows'].pop()
    assert not evaluation.report_passed(report)


def test_complete_failed_experiment_is_valid_observation_but_cannot_spoof_passed_status():
    report = complete_report()
    row = report['rows'][0]
    row['verdicts'][0]['verdict'] = 'true_positive'
    case = next(case for case in json.loads((evaluation.HERE/'cases.json').read_text())['cases'] if case['id'] == row['case_id'])
    verdict, _, row['scores'] = evaluation.score(case, row['response'], row)
    row['scores']['recommendation_transport'] = 1
    row['observed_verdict'] = verdict
    report['summary'] = evaluation.summarize(report['rows'])
    assert not evaluation.report_passed(report)
    with pytest.raises(ValueError, match='saved_report_status_mismatch'):
        evaluation.verify_saved_report(report)
    report['evaluation_status'] = 'failed'
    evaluation.verify_saved_report(report)


def test_legacy_incomplete_saved_report_is_refused_before_external_upload(tmp_path):
    legacy = {'schema_version': 1, 'planned_live_requests': 1, 'summary': {'live_cases': 1},
              'rows': [{'mode': 'live', 'case_id': 'a', 'pipeline_completed': True, 'scores': {}}]}
    target = tmp_path/'legacy.json'
    target.write_text(json.dumps(legacy))
    client = MagicMock()
    with pytest.raises(ValueError, match='unsupported_or_legacy_report_schema'):
        evaluation.upload_saved(argparse.Namespace(upload_only=target), client=client)
    assert client.mock_calls == []
    assert json.loads(target.read_text()) == legacy


def test_verify_only_cli_path_is_offline_and_does_not_mutate_saved_report(tmp_path, capsys):
    target = tmp_path/'report.json'
    report = complete_report()
    target.write_text(json.dumps(report))
    arguments = argparse.Namespace(verify_only=target, upload_only=None, cases=evaluation.HERE/'cases.json')
    assert evaluation.execute(arguments, argparse.ArgumentParser()) == 0
    assert json.loads(capsys.readouterr().out)['production_ready'] is False
    assert json.loads(target.read_text()) == report
    report['summary']['live_cases'] = 99
    target.write_text(json.dumps(report))
    assert evaluation.execute(arguments, argparse.ArgumentParser()) == 1
    assert json.loads(capsys.readouterr().out)['saved_report_valid'] is False


def test_verify_only_does_not_return_success_for_a_valid_but_failed_smoke(tmp_path, capsys):
    report = complete_report()
    row = report['rows'][0]
    row['raw_model_verdicts'][0]['fixed_code'] = 'return ('
    case = next(case for case in json.loads((evaluation.HERE/'cases.json').read_text())['cases'] if case['id'] == row['case_id'])
    row['replacement_validation'] = evaluation.replacement_validation(case, row)
    report['summary'] = evaluation.summarize(report['rows'])
    report['evaluation_status'] = 'failed'
    target = tmp_path/'failed.json'
    target.write_text(json.dumps(report))
    arguments = argparse.Namespace(verify_only=target, upload_only=None, cases=evaluation.HERE/'cases.json')
    assert evaluation.execute(arguments, argparse.ArgumentParser()) == 1
    result = json.loads(capsys.readouterr().out)
    assert result['saved_report_valid'] is True and result['smoke_passed'] is False


def test_upload_uses_scalar_allowlist_and_does_not_extend_retention(tmp_path):
    client = MagicMock()
    client.has_dataset.return_value = False
    client.create_dataset.return_value = SimpleNamespace(id='dataset')
    client.create_project.return_value = SimpleNamespace(id='project')
    client.list_examples.return_value = []
    client.create_example.return_value = SimpleNamespace(id='example')
    report = complete_report()
    timestamp = report['rows'][0]['started_at']
    report['rows'][0].update(raw_response='PRIVATE RESPONSE', prompt='PRIVATE PROMPT',
        stages=[{'name':'model','started_at':timestamp,'ended_at':timestamp,'elapsed_ms':9}],
        usage={'input_tokens':10,'output_tokens':5})
    report['rows'][0]['response']['source'] = 'PRIVATE CODE'
    target = tmp_path/'report.json'
    target.write_text(json.dumps(report))
    evaluation.upload_saved(argparse.Namespace(upload_only=target), client=client)
    sent = str(client.mock_calls)
    assert 'PRIVATE' not in sent
    assert client.create_run.call_count == 4
    assert client.create_run.call_args_list[1].kwargs['parent_run_id'] == client.create_run.call_args_list[0].kwargs['id']
    assert client.create_feedback.call_args.kwargs['extend_trace_retention'] is False
    client.read_run.assert_called_once()
    assert json.loads(target.read_text())['upload']['status'] == 'uploaded'
