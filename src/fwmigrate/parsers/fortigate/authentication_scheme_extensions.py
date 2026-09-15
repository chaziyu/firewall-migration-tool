"""FortiOS 7.4.6 authentication-scheme parser metadata."""


AUTHENTICATION_METHODS = {
    "ntlm", "basic", "digest", "form", "negotiate",
    "fsso", "rsso", "ssh-publickey", "cert", "saml",
}

AUTHENTICATION_SWITCH_FIELDS = {
    "fsso_guest", "negotiate_ntlm", "require_tfa", "user_cert",
}

AUTHENTICATION_STRING_LIMITS = {
    "domain_controller": 35,
    "fsso_agent_for_ntlm": 35,
    "kerberos_keytab": 35,
    "saml_server": 35,
    "ssh_ca": 35,
}
