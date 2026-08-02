from unittest import TestLoader

use_load_tests = False
TestLoader.loadTestsFromModule(TestLoader(), object(), use_load_tests)
