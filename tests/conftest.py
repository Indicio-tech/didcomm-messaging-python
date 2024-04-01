import pytest


def pytest_addoption(parser):
    parser.addoption(
        "--runexternal",
        action="store_true",
        default=False,
        help="run tests that make external requests",
    )


def pytest_configure(config):
    config.addinivalue_line("markers", "external_fetch: mark test as slow to run")


def pytest_collection_modifyitems(config, items):
    if config.getoption("--runexternal"):
        # --runslow given in cli: do not skip slow tests
        return
    skip_external = pytest.mark.skip(reason="need --runexternal option to run")
    for item in items:
        if "external_fetch" in item.keywords:
            item.add_marker(skip_external)
