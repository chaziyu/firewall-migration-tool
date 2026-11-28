"""Flask API tests for Phase 3 Traffic Simulators & Structural Config Diff."""

from __future__ import annotations

import io
import json

from fwmigrate.web import create_app

_FG_CONF = """#config-version=FGT60F-7.4.9-FW-build2829-250101:opmode=0:vdom=0:user=admin
config system interface
    edit "internal"
        set vdom "root"
        set ip 10.10.0.1 255.255.255.0
    next
    edit "wan1"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.248
    next
end
config router static
    edit 1
        set dst 0.0.0.0 0.0.0.0
        set gateway 198.51.100.1
        set device "wan1"
    next
end
config firewall policy
    edit 1
        set name "Allow_HTTPS"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "all"
        set dstaddr "all"
        set service "HTTPS"
        set action accept
        set nat enable
    next
end
"""

_FG_CONF_2 = _FG_CONF.replace('set name "Allow_HTTPS"', 'set name "Allow_HTTPS_V2"')

_PA_XML = """<config version="11.1.0">
  <devices><entry name="fw">
    <network>
      <interface><ethernet>
        <entry name="ethernet1/1"><link-state>up</link-state><layer3><ip><entry name="198.51.100.2/29"/></ip></layer3></entry>
        <entry name="ethernet1/2"><link-state>up</link-state><layer3><ip><entry name="10.10.0.1/24"/></ip></layer3></entry>
      </ethernet></interface>
      <virtual-router><entry name="default">
        <interface><member>ethernet1/1</member><member>ethernet1/2</member></interface>
        <routing-table><ip><static-route>
          <entry name="def"><destination>0.0.0.0/0</destination><interface>ethernet1/1</interface><nexthop><ip-address>198.51.100.1</ip-address></nexthop></entry>
        </static-route></ip></routing-table>
      </entry></virtual-router>
    </network>
    <vsys><entry name="vsys1">
      <zone>
        <entry name="untrust"><network><layer3><member>ethernet1/1</member></layer3></network></entry>
        <entry name="trust"><network><layer3><member>ethernet1/2</member></layer3></network></entry>
      </zone>
      <rulebase><security><rules>
        <entry name="Allow_HTTPS">
          <from><member>trust</member></from><to><member>untrust</member></to>
          <source><member>any</member></source><destination><member>any</member></destination>
          <service><member>service-https</member></service><action>allow</action>
        </entry>
      </rules></security></rulebase>
    </entry></vsys>
  </entry></devices>
</config>"""


def test_simulator_endpoints_fortigate_and_paloalto():
    client = create_app({"TESTING": True, "WEB_MODE": "public"}).test_client()
    fg_src = {"vendor": "fortigate", "source_text": _FG_CONF, "source_name": "fg1.conf"}
    pa_src = {"vendor": "palo_alto", "source_text": _PA_XML, "source_name": "pa1.xml"}

    # Policy lookup
    r = client.post("/api/source/policy-lookup", json={
        "source_vendor": "fortigate",
        "source": fg_src,
        "src_iface": "internal",
        "dst_iface": "wan1",
        "src_addr": "10.10.0.10",
        "dst_addr": "8.8.8.8",
        "protocol": "tcp/443",
    })
    assert r.status_code == 200
    assert r.get_json()["matched"] is True

    r_pa = client.post("/api/source/policy-lookup", json={
        "source_vendor": "palo_alto",
        "source": pa_src,
        "src_zone": "trust",
        "dst_zone": "untrust",
        "src_addr": "10.10.0.10",
        "dst_addr": "8.8.8.8",
        "protocol": "tcp",
        "dst_port": "443",
    })
    assert r_pa.status_code == 200
    assert r_pa.get_json()["matched"] is True

    # Route lookup
    rt = client.post("/api/source/route-lookup", json={
        "source_vendor": "fortigate",
        "source": fg_src,
        "dest_ip": "8.8.8.8",
    })
    assert rt.status_code == 200
    assert rt.get_json()["winner"]["interface"] == "wan1"

    rt_bad = client.post("/api/source/route-lookup", json={
        "source_vendor": "palo_alto",
        "source": pa_src,
        "dest_ip": "bad-ip",
    })
    assert rt_bad.status_code == 200
    assert rt_bad.get_json()["valid"] is False

    # Packet trace
    tr = client.post("/api/source/packet-trace", json={
        "source_vendor": "palo_alto",
        "source": pa_src,
        "src_ip": "10.10.0.10",
        "dst_ip": "8.8.8.8",
        "dst_port": "443",
        "protocol": "tcp",
    })
    assert tr.status_code == 200
    assert tr.get_json()["verdict"] == "ALLOW"

    # Config diff (multipart upload)
    diff_resp = client.post(
        "/api/source/config-diff",
        data={
            "source_vendor": "fortigate",
            "source": json.dumps(fg_src),
            "compare_file": (io.BytesIO(_FG_CONF_2.encode("utf-8")), "fg2.conf"),
        },
        content_type="multipart/form-data",
    )
    assert diff_resp.status_code == 200
    diff_data = diff_resp.get_json()
    assert diff_data["has_diff"] is True
    assert diff_data["summary"]["modified"] == 1

    # Cross-vendor mismatch rejected with 400
    cross = client.post(
        "/api/source/config-diff",
        data={
            "source_vendor": "fortigate",
            "source": json.dumps(fg_src),
            "compare_file": (io.BytesIO(_PA_XML.encode("utf-8")), "pa.xml"),
        },
        content_type="multipart/form-data",
    )
    assert cross.status_code == 400

    # Unsupported vendor rejected with 400
    bad_vendor = client.post("/api/source/policy-lookup", json={
        "source_vendor": "cisco_asa",
        "source": {"vendor": "cisco_asa", "source_text": ""},
    })
    assert bad_vendor.status_code == 400


def test_config_diff_large_multipart_source_and_source_digest_cache():
    client = create_app({"TESTING": True, "WEB_MODE": "local"}).test_client()
    pad_addrs = "\n".join(
        f'    edit "addr_{i}"\n        set subnet 10.{(i >> 8) & 255}.{i & 255}.0 255.255.255.0\n    next'
        for i in range(8500)
    )
    large_conf = f"{_FG_CONF}\nconfig firewall address\n{pad_addrs}\nend\n"
    assert len(large_conf.encode("utf-8")) > 550_000

    # 1. Multipart >500 KB source field succeeds (previously 413)
    fg_src = {"vendor": "fortigate", "source_text": large_conf, "source_name": "large.conf"}
    diff_resp = client.post(
        "/api/source/config-diff",
        data={
            "source_vendor": "fortigate",
            "source": json.dumps(fg_src),
            "compare_file": (io.BytesIO(large_conf.encode("utf-8")), "large_2.conf"),
        },
        content_type="multipart/form-data",
    )
    assert diff_resp.status_code == 200
    assert diff_resp.get_json()["has_diff"] is False

    # 2. Preview populates analysis_cache + sealed_source_store, enabling source_digest calls
    prev = client.post(
        "/api/preview",
        data={
            "source_vendor": "fortigate",
            "file": (io.BytesIO(large_conf.encode("utf-8")), "large.conf"),
        },
        content_type="multipart/form-data",
    )
    assert prev.status_code == 200
    digest = prev.get_json()["source_digest"]

    for ep, extra in (
        ("/api/source/audit", {}),
        ("/api/source/where-used", {"query": "10.0.1.0/24"}),
        ("/api/source/route-lookup", {"dest_ip": "8.8.8.8"}),
        ("/api/extract/excel", {"excel_profile": "fast"}),
    ):
        resp = client.post(ep, json={"source_vendor": "fortigate", "source_digest": digest, **extra})
        assert resp.status_code == 200

    diff_digest = client.post(
        "/api/source/config-diff",
        data={
            "source_vendor": "fortigate",
            "source_digest": digest,
            "compare_file": (io.BytesIO(large_conf.encode("utf-8")), "large_2.conf"),
        },
        content_type="multipart/form-data",
    )
    assert diff_digest.status_code == 200

    # 3. Unknown digest returns 410 source_expired
    expired = client.post("/api/source/audit", json={
        "source_vendor": "fortigate",
        "source_digest": "0" * 64,
    })
    assert expired.status_code == 410
    assert expired.get_json()["error_code"] == "source_expired"
