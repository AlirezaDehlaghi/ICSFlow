
import pytest

from Helper import maximum


def test_maximum():
    assert maximum([]) == ''
    assert maximum([2,3]) == 3
    assert maximum([2,3]) == 2
