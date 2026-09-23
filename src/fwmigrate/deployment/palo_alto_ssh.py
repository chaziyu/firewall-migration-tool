"""Optional SSH deployment for already-rendered Palo Alto commands."""

from .models import PANDeploymentOptions


def deploy_set_commands(commands, options: PANDeploymentOptions):
    try:
        from netmiko import ConnectHandler
    except ImportError as exc:
        raise RuntimeError("SSH deployment requires optional dependency netmiko") from exc
    connection = ConnectHandler(device_type="paloalto_panos", host=options.host, username=options.username, password=options.password)
    try:
        connection.config_mode()
        output = connection.send_config_set(list(commands))
        if options.validate:
            output += connection.send_command("validate full")
        if options.commit:
            output += connection.commit()
        return output
    finally:
        connection.disconnect()
