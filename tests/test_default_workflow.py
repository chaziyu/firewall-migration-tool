import pytest

from fwmigrate.web import create_app


@pytest.fixture
def client():
    app = create_app({"TESTING": True})
    return app.test_client()


def test_extract_is_first_workspace_option_and_default(client):
    response = client.get("/")

    assert response.status_code == 200
    html = response.data
    assert html.index(b'id="tab-extract"') < html.index(b'id="tab-download"')
    assert html.index(b'id="tab-download"') < html.index(b'id="tab-live"')
    assert b'data-default-workflow="extract"' in html
    assert b'default_workflow.js' in html


def test_default_workflow_bootstrap_keeps_convert_available(client):
    response = client.get("/static/default_workflow.js")

    assert response.status_code == 200
    script = response.data
    assert b'dataset.defaultWorkflow' in script
    assert b'defaultTab.click()' in script
    assert b'querySelectorAll(\'[role="tab"]\')' in script


def test_compact_sidebar_styles_are_loaded(client):
    bootstrap = client.get("/static/default_workflow.js")
    stylesheet = client.get("/static/sidebar_compact.css")

    assert bootstrap.status_code == 200
    assert b"sidebar_compact.css?v=1.0" in bootstrap.data
    assert stylesheet.status_code == 200
    assert b".sidebar-bottom" in stylesheet.data
    assert b"margin-top: 28px" in stylesheet.data
    assert b"padding-top: 0" in stylesheet.data
    assert b"max-height: 760px" in stylesheet.data
