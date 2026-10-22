import pytest
from mock import patch

from pip._internal.cli.req_command import (
    IndexGroupCommand,
    RequirementCommand,
    SessionCommandMixin,
)
from pip._internal.cli.status_codes import SUCCESS
from pip._internal.commands import commands_dict, create_command
from pip._internal.commands.install import _arg_refers_to_pip

# These are the expected names of the commands whose classes inherit from
# IndexGroupCommand.
EXPECTED_INDEX_GROUP_COMMANDS = ['download', 'install', 'list', 'wheel']


def check_commands(pred, expected):
    """
    Check the commands satisfying a predicate.
    """
    commands = [create_command(name) for name in sorted(commands_dict)]
    actual = [command.name for command in commands if pred(command)]
    assert actual == expected, 'actual: {}'.format(actual)


def test_commands_dict__order():
    """
    Check the ordering of commands_dict.
    """
    names = list(commands_dict)
    # A spot-check is sufficient to check that commands_dict encodes an
    # ordering.
    assert names[0] == 'install'
    assert names[-1] == 'help'


@pytest.mark.parametrize('name', list(commands_dict))
def test_create_command(name):
    """Test creating an instance of each available command."""
    command = create_command(name)
    assert command.name == name
    assert command.summary == commands_dict[name].summary


def test_session_commands():
    """
    Test which commands inherit from SessionCommandMixin.
    """
    def is_session_command(command):
        return isinstance(command, SessionCommandMixin)

    expected = ['download', 'install', 'list', 'search', 'uninstall', 'wheel']
    check_commands(is_session_command, expected)


def test_index_group_commands():
    """
    Test the commands inheriting from IndexGroupCommand.
    """
    def is_index_group_command(command):
        return isinstance(command, IndexGroupCommand)

    check_commands(is_index_group_command, EXPECTED_INDEX_GROUP_COMMANDS)

    # Also check that the commands inheriting from IndexGroupCommand are
    # exactly the commands with the --no-index option.
    def has_option_no_index(command):
        return command.parser.has_option('--no-index')

    check_commands(has_option_no_index, EXPECTED_INDEX_GROUP_COMMANDS)


@pytest.mark.parametrize('command_name', EXPECTED_INDEX_GROUP_COMMANDS)
@pytest.mark.parametrize(
    'disable_pip_version_check, no_index, expected_called',
    [
        # pip_self_version_check() is only called when both
        # disable_pip_version_check and no_index are False.
        (False, False, True),
        (False, True, False),
        (True, False, False),
        (True, True, False),
    ],
)
@patch('pip._internal.cli.req_command.pip_self_version_check')
def test_index_group_handle_pip_version_check(
    mock_version_check, command_name, disable_pip_version_check, no_index,
    expected_called,
):
    """
    Test whether pip_self_version_check() is called when
    handle_pip_version_check() is called, for each of the
    IndexGroupCommand classes.
    """
    command = create_command(command_name)
    options = command.parser.get_default_values()
    options.disable_pip_version_check = disable_pip_version_check
    options.no_index = no_index

    command.handle_pip_version_check(options)
    if expected_called:
        mock_version_check.assert_called_once()
    else:
        mock_version_check.assert_not_called()


def test_requirement_commands():
    """
    Test which commands inherit from RequirementCommand.
    """
    def is_requirement_command(command):
        return isinstance(command, RequirementCommand)

    check_commands(is_requirement_command, ['download', 'install', 'wheel'])


@pytest.mark.parametrize('command_name', EXPECTED_INDEX_GROUP_COMMANDS)
def test_index_group_version_check_runs_before_command_body(
    monkeypatch, command_name,
):
    """
    CVE-2026-6357: the self-version check must do its lookups before the
    command body (which may install packages) and only report afterwards.
    Run after `pip install`, the lookup computes supported tags, which
    probes ``import _manylinux`` and could execute a just-installed module.
    """
    # The isolate fixture disables the check through the environment.
    monkeypatch.delenv('PIP_DISABLE_PIP_VERSION_CHECK', raising=False)
    events = []
    fetched = object()

    def fake_fetch(session, options):
        events.append('fetch')
        return fetched

    def fake_emit(prompt):
        events.append(('emit', prompt is fetched))

    def fake_full_check(session, options):
        events.append('full-check')

    monkeypatch.setattr(
        'pip._internal.cli.req_command._pip_self_version_check_fetch',
        fake_fetch,
    )
    monkeypatch.setattr(
        'pip._internal.cli.req_command._pip_self_version_check_emit',
        fake_emit,
    )
    monkeypatch.setattr(
        'pip._internal.cli.req_command.pip_self_version_check',
        fake_full_check,
    )

    command = create_command(command_name)

    def fake_run(options, args):
        events.append('run')
        return SUCCESS

    monkeypatch.setattr(command, 'run', fake_run)

    assert command.main([]) == SUCCESS
    assert events == ['fetch', 'run', ('emit', True)]


@pytest.mark.parametrize('command_name', EXPECTED_INDEX_GROUP_COMMANDS)
@pytest.mark.parametrize('extra_args', [
    ['--disable-pip-version-check'],
    ['--no-index'],
])
def test_index_group_version_check_disabled(
    monkeypatch, command_name, extra_args,
):
    events = []
    monkeypatch.setattr(
        'pip._internal.cli.req_command._pip_self_version_check_fetch',
        lambda session, options: events.append('fetch'),
    )
    monkeypatch.setattr(
        'pip._internal.cli.req_command._pip_self_version_check_emit',
        lambda prompt: events.append(('emit', prompt)),
    )
    command = create_command(command_name)
    monkeypatch.setattr(command, 'run', lambda options, args: SUCCESS)

    assert command.main(extra_args) == SUCCESS
    assert events == [('emit', None)]


@pytest.mark.parametrize('arg, expected', [
    ('pip', True),
    ('PIP==20.3.4', True),
    ('pip>=20', True),
    ('pip[foo]', True),
    ('pipx', False),
    ('six', False),
    ('./pip-20.3.4-py2.py3-none-any.whl', False),
    ('-r', False),
    # urlparse raises ValueError for this URL; it is simply not pip.
    ('foo @ http://[bad/x', False),
])
def test_arg_refers_to_pip(arg, expected):
    assert _arg_refers_to_pip(arg) is expected


def test_install_skips_version_check_when_installing_pip(monkeypatch):
    calls = []
    monkeypatch.setattr(
        'pip._internal.cli.req_command._pip_self_version_check_fetch',
        lambda session, options: calls.append('fetch'),
    )
    command = create_command('install')
    options = command.parser.get_default_values()
    options.disable_pip_version_check = False
    options.no_index = False

    assert command._pip_version_check_fetch(options, ['pip']) is None
    assert calls == []

    command._pip_version_check_fetch(options, ['six'])
    assert calls == ['fetch']
