from __future__ import annotations

import os
import sys

from flask import render_template

from fwmigrate.live_source_api import register_live_source_routes
from fwmigrate.web import DesktopAPI, create_app as create_base_app


def create_app(test_config=None):
    """Create the standard web app with live source extraction routes enabled."""
    app = create_base_app(test_config=test_config)
    register_live_source_routes(app)

    @app.route('/live-source')
    def live_source_page():
        return render_template('live_source.html')

    return app


def run_desktop(port: int = 5000):
    """Launch the desktop UI with live source extraction enabled."""
    app = create_app()
    try:
        import webview

        api = DesktopAPI()
        window = webview.create_window(
            title="Firewall Migration Tool",
            url=app,
            width=1360,
            height=880,
            min_size=(960, 640),
            text_select=True,
            js_api=api,
        )
        api.set_window(window)
        webview.start(gui='edgechromium')
    except ImportError:
        import webbrowser

        url = f"http://localhost:{port}/live-source"
        print(f"pywebview is not installed. Opening in default browser at {url}")
        webbrowser.open(url)
        app.run(host='127.0.0.1', port=port, debug=False)
