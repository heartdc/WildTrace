"""Deterministic gate for requesting local safety verification."""
def can_request_local_verification(*, workflow_state, recheck_results):
    if workflow_state != 'static_scan':
        return False, 'workflow must be static_scan'
    if not isinstance(recheck_results, list) or not recheck_results:
        return False, 'at least one recheck is required'
    if any(not isinstance(item, dict) or item.get('reproducible') is not True for item in recheck_results):
        return False, 'all candidate evidence must be reproducible'
    return True, 'ready for isolated local harness review'

def request_local_verification_transition(*, workflow_state, recheck_results):
    """Return the next FSM intent; caller must perform the actual transition."""
    ready, reason = can_request_local_verification(workflow_state=workflow_state, recheck_results=recheck_results)
    if not ready:
        raise ValueError(reason)
    return 'local_verification'
