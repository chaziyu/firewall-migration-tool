"""Single-process hosting: application sessions and request controls live in memory."""

workers = 1
threads = 4


def on_starting(server):
    if server.cfg.workers != 1:
        raise RuntimeError('fwmigrate requires exactly one Gunicorn worker and one application instance')


def nworkers_changed(server, new_value, old_value):
    if new_value != 1:
        raise RuntimeError('fwmigrate requires exactly one Gunicorn worker and one application instance')
