"""Human-readable guidance for blocked PAN-OS to ASA cases."""


def support_guidance(blockers):
    return tuple(code.replace("_", " ").capitalize() + "." for code in dict.fromkeys(blockers))
