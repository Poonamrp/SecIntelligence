import responses
import pytest
from src.collectors.rss import RssFeedCollector

SAMPLE_RSS_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Test Security Feed</title>
    <link>https://vendor.example.com</link>
    <description>Security alerts and bulletins</description>
    <item>
      <title>High Severity Vulnerability in SecureCore (CVE-2024-8008)</title>
      <link>https://vendor.example.com/alerts/2024-01</link>
      <description>A High severity buffer overflow exists in SecureCore before 4.2.</description>
      <pubDate>Wed, 12 Jun 2024 14:00:00 GMT</pubDate>
      <guid>https://vendor.example.com/alerts/2024-01</guid>
    </item>
  </channel>
</rss>
"""

@responses.activate
def test_rss_feed_collector():
    collector = RssFeedCollector(
        source_name="Vendor RSS Test",
        base_url="https://vendor.example.com/feed.xml"
    )

    responses.add(
        responses.GET,
        "https://vendor.example.com/feed.xml",
        body=SAMPLE_RSS_FEED,
        status=200,
        content_type="application/rss+xml"
    )

    advisories = collector.collect()
    assert len(advisories) == 1
    adv = advisories[0]

    assert adv.cve_id == "CVE-2024-8008"
    assert adv.stable_key == "CVE-2024-8008"
    assert adv.severity == "High"
    assert adv.canonical_url == "https://vendor.example.com/alerts/2024-01"
