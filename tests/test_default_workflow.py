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


def test_header_is_removed_and_theme_toggle_follows_new_workspace(client):
    response = client.get("/")

    assert response.status_code == 200
    html = response.data
    assert b'class="topbar"' not in html
    assert html.index(b'id="btn-new-workspace"') < html.index(b'id="btn-toggle-theme"')
    assert html.index(b'id="btn-toggle-theme"') < html.index(b'class="workspace-grid"')


def test_workflow_step_strip_is_removed(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b'class="workflow-track' not in response.data


def test_bottom_right_guidance_is_removed(client):
    response = client.get("/")

    assert response.status_code == 200
    assert b"A good migration starts here" not in response.data
    assert b"File processing runs in this application" not in response.data


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
    assert b"sidebar_compact.css?v=1.1" in bootstrap.data
    assert stylesheet.status_code == 200
    assert b".sidebar-bottom" in stylesheet.data
    assert b"margin-top: auto" in stylesheet.data
    assert b"padding-top: 0" in stylesheet.data
    assert b"max-height: 760px" in stylesheet.data


def test_light_theme_has_a_light_sidebar_palette(client):
    stylesheet = client.get("/static/themes.css")

    assert stylesheet.status_code == 200
    assert b'[data-theme="light"] .sidebar' in stylesheet.data
    assert b'[data-theme="light"] .tab-btn.active' in stylesheet.data
    assert b'--text-muted: #4f5f57' in stylesheet.data
    assert b'[data-theme="light"] .dropzone-formats' in stylesheet.data
