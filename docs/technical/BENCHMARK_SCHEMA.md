# Benchmark Dataset Schema

This schema defines a minimal, reproducible benchmark dataset for evaluating
precision/recall of platform-specific and OWASP-aligned findings.

## Dataset Metadata
- `dataset_version`: string
- `generated_at`: ISO-8601 timestamp
- `description`: string

## Target Entry
- `id`: string
- `platform`: string (bubble, outsystems, airtable, shopify, webflow, wix, mendix, generic)
- `url`: string
- `expected_findings`: list

## Expected Finding
- `id`: string
- `type`: string
- `severity`: string
- `owasp`: string
- `evidence`: string or object
- `notes`: string (optional)

## Example
```json
{
  "dataset_version": "v0.1",
  "generated_at": "2026-02-06T00:00:00Z",
  "description": "Minimal benchmark for thesis evaluation.",
  "targets": [
    {
      "id": "bubble-001",
      "platform": "bubble",
      "url": "https://example.bubbleapps.io/version-test/",
      "expected_findings": [
        {
          "id": "bubble-001-1",
          "type": "Bubble Workflow Exposure",
          "severity": "High",
          "owasp": "A01:2021 - Broken Access Control",
          "evidence": "api/1.1/wf/",
          "notes": "Workflow endpoint found in client code."
        }
      ]
    }
  ]
}
```

