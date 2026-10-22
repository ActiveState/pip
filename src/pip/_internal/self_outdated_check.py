import datetime
import hashlib
import json
import logging
import optparse
import os.path
import sys
from typing import Any, Dict, NamedTuple, Optional

from pip._vendor.packaging.version import parse as parse_version

from pip._internal.index.collector import LinkCollector
from pip._internal.index.package_finder import PackageFinder
from pip._internal.metadata import get_default_environment
from pip._internal.models.selection_prefs import SelectionPreferences
from pip._internal.network.session import PipSession
from pip._internal.utils.filesystem import adjacent_tmp_file, check_path_owner, replace
from pip._internal.utils.misc import ensure_dir

SELFCHECK_DATE_FMT = "%Y-%m-%dT%H:%M:%SZ"


logger = logging.getLogger(__name__)


def _get_statefile_name(key: str) -> str:
    key_bytes = key.encode()
    name = hashlib.sha224(key_bytes).hexdigest()
    return name


class SelfCheckState:
    def __init__(self, cache_dir: str) -> None:
        self.state: Dict[str, Any] = {}
        self.statefile_path = None

        # Try to load the existing state
        if cache_dir:
            self.statefile_path = os.path.join(
                cache_dir, "selfcheck", _get_statefile_name(self.key)
            )
            try:
                with open(self.statefile_path, encoding="utf-8") as statefile:
                    self.state = json.load(statefile)
            except (OSError, ValueError, KeyError):
                # Explicitly suppressing exceptions, since we don't want to
                # error out if the cache file is invalid.
                pass

    @property
    def key(self) -> str:
        return sys.prefix

    def save(self, pypi_version: str, current_time: datetime.datetime) -> None:
        # If we do not have a path to cache in, don't bother saving.
        if not self.statefile_path:
            return

        # Check to make sure that we own the directory
        if not check_path_owner(os.path.dirname(self.statefile_path)):
            return

        # Now that we've ensured the directory is owned by this user, we'll go
        # ahead and make sure that all our directories are created.
        ensure_dir(os.path.dirname(self.statefile_path))

        state = {
            # Include the key so it's easy to tell which pip wrote the
            # file.
            "key": self.key,
            "last_check": current_time.strftime(SELFCHECK_DATE_FMT),
            "pypi_version": pypi_version,
        }

        text = json.dumps(state, sort_keys=True, separators=(",", ":"))

        with adjacent_tmp_file(self.statefile_path) as f:
            f.write(text.encode())

        try:
            # Since we have a prefix-specific state file, we can just
            # overwrite whatever is there, no need to check.
            replace(f.name, self.statefile_path)
        except OSError:
            # Best effort.
            pass


class UpgradePrompt(NamedTuple):
    """The upgrade prompt computed before a command runs."""

    old: str
    new: str


def pip_self_version_check_fetch(
    session: PipSession, options: optparse.Values
) -> Optional[UpgradePrompt]:
    """Compute the pip upgrade prompt, if any, before the command runs.

    Limit the frequency of checks to once per week. State is stored either in
    the active virtualenv or in the user's USER_CACHE_DIR keyed off the prefix
    of the pip script path.

    Everything that inspects the environment or builds a PackageFinder lives
    here, so it runs before the command body has installed anything. Pair with
    :func:`pip_self_version_check_emit`, which only displays the prompt after
    the command body runs (CVE-2026-6357).
    """
    installed_dist = get_default_environment().get_distribution("pip")
    if not installed_dist:
        return None

    pip_version = installed_dist.version
    pypi_version = None

    try:
        state = SelfCheckState(cache_dir=options.cache_dir)

        current_time = datetime.datetime.utcnow()
        # Determine if we need to refresh the state
        if "last_check" in state.state and "pypi_version" in state.state:
            last_check = datetime.datetime.strptime(
                state.state["last_check"], SELFCHECK_DATE_FMT
            )
            if (current_time - last_check).total_seconds() < 7 * 24 * 60 * 60:
                pypi_version = state.state["pypi_version"]

        # Refresh the version if we need to or just see if we need to warn
        if pypi_version is None:
            # Lets use PackageFinder to see what the latest pip version is
            link_collector = LinkCollector.create(
                session,
                options=options,
                suppress_no_index=True,
            )

            # Pass allow_yanked=False so we don't suggest upgrading to a
            # yanked version.
            selection_prefs = SelectionPreferences(
                allow_yanked=False,
                allow_all_prereleases=False,  # Explicitly set to False
            )

            finder = PackageFinder.create(
                link_collector=link_collector,
                selection_prefs=selection_prefs,
            )
            best_candidate = finder.find_best_candidate("pip").best_candidate
            if best_candidate is None:
                return None
            pypi_version = str(best_candidate.version)

            # save that we've performed a check
            state.save(pypi_version, current_time)

        remote_version = parse_version(pypi_version)

        local_version_is_older = (
            pip_version < remote_version
            and pip_version.base_version != remote_version.base_version
            # Only suggest an upgrade when pip was installed by pip, not by a
            # system package manager such as dnf on Fedora. Read from the dist
            # found above instead of re-querying the environment later.
            and installed_dist.installer == "pip"
        )

        # Determine if our pypi_version is older
        if not local_version_is_older:
            return None

        return UpgradePrompt(old=str(pip_version), new=pypi_version)
    except Exception:
        logger.debug(
            "There was an error checking the latest version of pip",
            exc_info=True,
        )
        return None


def pip_self_version_check_emit(upgrade_prompt: Optional[UpgradePrompt]) -> None:
    """Emit the upgrade prompt captured by :func:`pip_self_version_check_fetch`.

    This only logs; it must not import anything or inspect the environment,
    because it runs after packages may have been installed.
    """
    if upgrade_prompt is None:
        return

    # We cannot tell how the current pip is available in the current
    # command context, so be pragmatic here and suggest the command
    # that's always available. This does not accommodate spaces in
    # `sys.executable`.
    pip_cmd = f"{sys.executable} -m pip"
    logger.warning(
        "You are using pip version %s; however, version %s is "
        "available.\nYou should consider upgrading via the "
        "'%s install --upgrade pip' command.",
        upgrade_prompt.old,
        upgrade_prompt.new,
        pip_cmd,
    )


def pip_self_version_check(session: PipSession, options: optparse.Values) -> None:
    """Check for an update for pip and emit the prompt immediately.

    Kept for callers of the pre-CVE-2026-6357 API. pip itself no longer uses
    it: commands fetch before running and emit afterwards (see
    ``IndexGroupCommand.pip_version_check``).
    """
    pip_self_version_check_emit(pip_self_version_check_fetch(session, options))
