def pytest_configure(config):
    config.addinivalue_line("markers", "slow: tests that wait for timeouts (deselect with -m 'not slow')")
