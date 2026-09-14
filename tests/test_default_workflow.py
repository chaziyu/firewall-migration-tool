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
