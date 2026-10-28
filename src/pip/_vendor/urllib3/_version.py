# This file is protected via CODEOWNERS
# ActiveState security release. The package metadata carries the post-release
# (__package_version__, which setup.py reads), while __version__ stays
# "1.26.20": requests unpacks urllib3.__version__ as major.minor.patch and
# emits RequestsDependencyWarning for anything longer.
__version__ = "1.26.20"
__package_version__ = "1.26.20.post4"
