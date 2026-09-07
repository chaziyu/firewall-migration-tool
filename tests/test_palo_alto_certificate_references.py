from fwmigrate.parsers.palo_alto.parser import PANOSSourceParser


def _extract(shared_body: str):
    return PANOSSourceParser().extract(f"<config><shared>{shared_body}</shared></config>")


def test_ssl_tls_service_profile_does_not_treat_certificate_profile_as_certificate():
    result = _extract(
        '<certificate-profile><entry name="client-cert-profile" /></certificate-profile>'
        '<ssl-tls-service-profile><entry name="tls-profile">'
        '<certificate-profile>client-cert-profile</certificate-profile>'
        '</entry></ssl-tls-service-profile>'
    )

    profile = result.canonical_ir.ssl_tls_service_profiles[0]

    assert profile.certificate is None
    assert profile.certificate_resolved is None
    assert profile.source_attributes["pan_certificate_profile_reference"] == "client-cert-profile"
    assert "unexpected-certificate-profile-reference" in profile.review_reasons
    assert "unresolved-certificate-reference" not in profile.review_reasons


def test_ssl_tls_service_profile_keeps_certificate_and_certificate_profile_distinct():
    result = _extract(
        '<certificate><entry name="server-cert"><public-key>CERT</public-key></entry></certificate>'
        '<certificate-profile><entry name="client-cert-profile" /></certificate-profile>'
        '<ssl-tls-service-profile><entry name="tls-profile">'
        '<certificate>server-cert</certificate>'
        '<certificate-profile>client-cert-profile</certificate-profile>'
        '</entry></ssl-tls-service-profile>'
    )

    profile = result.canonical_ir.ssl_tls_service_profiles[0]

    assert profile.certificate == "server-cert"
    assert profile.certificate_resolved is True
    assert profile.source_attributes["pan_certificate_profile_reference"] == "client-cert-profile"
    assert "unexpected-certificate-profile-reference" in profile.review_reasons
