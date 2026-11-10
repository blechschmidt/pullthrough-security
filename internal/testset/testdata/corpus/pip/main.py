"""Minimal real pip build for the pull-through proxy test set."""
import six

assert six.PY3 or six.PY2
print("six", six.__version__, "ok")
