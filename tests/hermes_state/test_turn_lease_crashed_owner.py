"""An OS-held owner lock proves liveness across container PID namespaces."""
import os
import subprocess
import sys
import uuid

import pytest

from hermes_state import SessionDB


@pytest.mark.platforms('posix')
def test_crashed_foreign_namespace_owner_is_reclaimed_before_ttl(tmp_path, monkeypatch):
    import hermes_state_pidns
    monkeypatch.setattr(hermes_state_pidns, "_LOCAL_PID_NS", hermes_state_pidns.LocalPidNamespace("111", True))
    db = SessionDB(tmp_path / 'state.db')
    db.create_session('chat', source='test')
    token = uuid.uuid4().hex
    directory = tmp_path / 'state.db.turn-owners'
    directory.mkdir()
    path = directory / token
    child = subprocess.Popen([sys.executable, '-u', '-c',
        'import fcntl,sys; f=open(sys.argv[1],"w+b"); fcntl.flock(f,fcntl.LOCK_EX); print("ready"); sys.stdin.read()', str(path)],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    try:
        assert child.stdout.readline().strip() == 'ready'
        old = f'pid={child.pid}:pidns=222:turn=old:platform=smartbuddy:owner={token}'
        assert db.try_acquire_session_turn_lease('chat', old, ttl_seconds=300)
        new = f'pid={os.getpid()}:turn=new:platform=smartbuddy'
        assert not db.try_acquire_session_turn_lease('chat', new)
        child.kill()
        child.wait(timeout=10)
        assert db.try_acquire_session_turn_lease('chat', new), 'dead owner must not impose the 300s lease TTL'
        assert not path.exists()
    finally:
        if child.poll() is None:
            child.kill()
        child.wait(timeout=10)
        db.close()


@pytest.mark.platforms('posix', 'windows')
def test_turn_admission_holds_proof_until_durable_release(tmp_path, monkeypatch):
    from types import SimpleNamespace
    from agent.turn_facade_lease import admit_durable_turn_lease, DurableTurnLease
    from hermes_state_turn_owner import turn_owner_is_dead
    monkeypatch.setattr(DurableTurnLease, 'build_threads', lambda self: None)
    db = SessionDB(tmp_path / 'state.db')
    db.create_session('chat', source='test')
    agent = SimpleNamespace(_session_db=db, _persist_disabled=False, _interrupt_requested=False,
                            _emit_status=lambda text: None, session_id='chat')
    admission = admit_durable_turn_lease(agent, session_id='chat', relay_turn_id='first',
                                        task_context={'platform': 'smartbuddy'}, conversation_history=None)
    lease = admission.lease
    try:
        assert lease is not None
        assert f':owner={lease.owner.token}' in lease.holder
        assert lease.owner.path.exists()
        assert not turn_owner_is_dead(db.db_path, lease.holder)
        assert not db.try_acquire_session_turn_lease('chat', 'other')
    finally:
        if lease is not None:
            lease.release()
    assert not lease.owner.path.exists()
    assert db.try_acquire_session_turn_lease('chat', 'other')
    db.close()


def test_missing_owner_proof_does_not_reclaim_unknown_namespace(tmp_path, monkeypatch):
    import hermes_state_pidns
    monkeypatch.setattr(hermes_state_pidns, '_LOCAL_PID_NS', hermes_state_pidns.LocalPidNamespace('111', True))
    db = SessionDB(tmp_path / 'state.db')
    db.create_session('chat', source='test')
    old = f'pid=123:pidns=222:turn=old:owner={uuid.uuid4().hex}'
    assert db.try_acquire_session_turn_lease('chat', old)
    assert not db.try_acquire_session_turn_lease('chat', 'contender')
    db.close()
