
import pytest

from Helper import maximum, minimum
    assert maximum([]) == ''
    assert maximum([2,3]) == 3
    

def test_minimum():   
    assert minimum([]) == ''
    assert minimum([2,3]) == 2
