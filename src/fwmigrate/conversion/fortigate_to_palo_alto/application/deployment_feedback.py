import re


def deployment_validation_feedback(rendered, decision_document, validation):
    if getattr(validation, 'status', None) != 'FAILED':
        return None
    response = str(getattr(validation, 'response', '') or '')
    decisions = decision_document.get('decisions', ()) if isinstance(decision_document, dict) else ()
    items = rendered.report.get('items', ())
    matches = [item for item in items if item.get('target_name') and
               re.search(rf'(?<![A-Za-z0-9_.-]){re.escape(item["target_name"])}(?![A-Za-z0-9_.-])', response, re.I)]
    candidates = []
    known_decisions = {decision.get('key') for decision in decisions if isinstance(decision, dict)}
    for item in matches:
        item_decisions = [key for key in item.get('decision_keys', ()) if key in known_decisions]
        candidates.append({**{key: item.get(key) for key in
            ('source_vdom', 'source_kind', 'source_name', 'target_name')},
            'decision_keys': item_decisions, 'generated_commands': list(item.get('commands', ()))})
    return {'status': 'FAILED', 'message': response,
            'mapping_status': 'MAPPED' if len(candidates) == 1 else 'AMBIGUOUS' if candidates else 'UNMAPPED',
            'migration_items': candidates}
