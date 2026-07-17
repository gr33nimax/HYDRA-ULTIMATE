from hydra.plugins.warp.clash_rules import parse_clash_rule_provider


def test_parse_classical_provider_rules():
    parsed = parse_clash_rule_provider(
        """payload:
  - DOMAIN,api.example.com
  - DOMAIN-SUFFIX,example.org
  - DOMAIN-KEYWORD,streaming
  - IP-CIDR,192.0.2.0/24,no-resolve
  - PROCESS-NAME,ignored
""",
        "classical",
    )
    assert parsed["domains"] == ["api.example.com"]
    assert parsed["domain_suffix"] == ["example.org"]
    assert parsed["domain_keyword"] == ["streaming"]
    assert parsed["ips"] == ["192.0.2.0/24"]
    assert parsed["skipped"] == 1


def test_parse_domain_text_provider():
    parsed = parse_clash_rule_provider(
        "# comment\n+.example.com\n.example.org\nplain.test\n",
        "domain",
        "text",
    )
    assert parsed["domain_suffix"] == ["example.com", "example.org", "plain.test"]
