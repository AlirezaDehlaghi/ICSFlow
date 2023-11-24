
import pytest

from Helper import maximum


def test_maximum():
    assert maximum([]) == 0

def test_maximum():
    assert maximum([2,3]) == 3


def test_maximum():
    assert maximum([2,3]) == 2
