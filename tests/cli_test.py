import pytest

from flask import Flask
from click.testing import CliRunner

from moe_gthr_auth_server import register_blueprints, register_error_handlers, db
from moe_gthr_auth_server.cli import initdb_command, resetdb_command
from testing_helpers import LOGGER


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def app():
    app = Flask("moe_gatherer_server")
    app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    app.config["TESTING"] = True
    LOGGER.debug("app: %s", app)
    register_blueprints(app)
    register_error_handlers(app)
    db.init_app(app)
    yield app


@pytest.fixture
def flask_cli_runner(app):
    return app.test_cli_runner()


def test_cli_help(flask_cli_runner):
    result = flask_cli_runner.invoke(args=["--help"])
    LOGGER.debug("result: %s", result.output)
    assert result.exit_code == 0
    assert "initdb" in result.output
    assert "resetdb" in result.output


def test_cli_resetdb(flask_cli_runner):
    result = flask_cli_runner.invoke(resetdb_command)
    LOGGER.debug("result: %s", result.output)
    assert result.exit_code == 0, result.output
    assert "adminler" in result.output


def test_cli_initdb_recrate(flask_cli_runner):
    result = flask_cli_runner.invoke(initdb_command, args=["--recreate"])
    LOGGER.debug("result: %s", result.output)
    assert result.exit_code == 0, result.output
    assert "adminler" in result.output


if __name__ == "__main__":
    pytest.main(["-vv", __file__])