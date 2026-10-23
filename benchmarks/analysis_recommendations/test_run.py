import argparse
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

spec = importlib.util.spec_from_file_location('recommendation_eval', Path(__file__).with_name('run.py'))
evaluation = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evaluation)


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
    row = {'mode': 'live', 'case_id': 'a', 'pipeline_completed': True,
           'elapsed_ms': 1, 'scores': {'verdict_match': 1},
           'replacement_validation': {'status': 'rejected'}}
    report = {'planned_live_requests': 1, 'rows': [row],
              'summary': evaluation.summarize([row])}
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
    live = {'mode':'live','case_id':'a','elapsed_ms':10,'pipeline_completed':False,
            'scores':{'verdict_match':1,'parsed_verdict':1,'one_model_call':1}}
    fault = {'mode':'timeout','case_id':'a','pipeline_completed':True,
             'fault_exercised':True,'fallback_preserved':True}
    report = {'planned_live_requests':1,'rows':[live, fault],
              'summary':evaluation.summarize([live, fault])}
    assert evaluation.report_passed(report) is False

    live['pipeline_completed'] = True
    fault['fault_exercised'] = False
    report['summary'] = evaluation.summarize([live, fault])
    assert evaluation.report_passed(report) is False

    fault['fault_exercised'] = True
    report['summary'] = evaluation.summarize([live, fault])
    assert evaluation.report_passed(report) is True


def test_upload_uses_scalar_allowlist_and_does_not_extend_retention(tmp_path):
    client = MagicMock()
    client.has_dataset.return_value = False
    client.create_dataset.return_value = SimpleNamespace(id='dataset')
    client.create_project.return_value = SimpleNamespace(id='project')
    client.list_examples.return_value = []
    client.create_example.return_value = SimpleNamespace(id='example')
    timestamp = '2026-10-05T12:00:00+00:00'
    report = {'model':'test-model','fixture_digest':'abc','prompt_digest':'def',
              'results_kind':'live_recommendation_smoke','rows':[{
                  'case_id':'a','mode':'live','repeat':1,'expected_verdict':'true_positive',
                  'observed_verdict':'true_positive','started_at':timestamp,'ended_at':timestamp,
                  'elapsed_ms':10,'raw_response':'PRIVATE RESPONSE','prompt':'PRIVATE PROMPT',
                  'response':{'source':'PRIVATE CODE'},'scores':{'verdict_match':1},
                  'stages':[{'name':'model','started_at':timestamp,'ended_at':timestamp,'elapsed_ms':9}],
                  'usage':{'input_tokens':10,'output_tokens':5}}]}
    target = tmp_path/'report.json'
    target.write_text(json.dumps(report))
    evaluation.upload_saved(argparse.Namespace(upload_only=target), client=client)
    sent = str(client.mock_calls)
    assert 'PRIVATE' not in sent
    assert client.create_run.call_count == 2
    assert client.create_run.call_args_list[1].kwargs['parent_run_id'] == client.create_run.call_args_list[0].kwargs['id']
    assert client.create_feedback.call_args.kwargs['extend_trace_retention'] is False
    client.read_run.assert_called_once()
    assert json.loads(target.read_text())['upload']['status'] == 'uploaded'
