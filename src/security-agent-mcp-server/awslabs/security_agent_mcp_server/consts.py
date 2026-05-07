# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Constants for the AWS Security Agent MCP Server."""

# Default configuration
DEFAULT_REGION = 'us-east-1'

# MCP Server instructions
SERVER_INSTRUCTIONS = """
# AWS Security Agent MCP Server

This MCP server enables automated security code review scanning before publishing code reviews.

## Available Tools

### Setup (one-time)
- `setup_check` — Verify prerequisites (credentials, agent space, role, bucket)
- `setup` — Auto-provision or reuse resources (agent space, S3 bucket, IAM role)

### Scanning
- `start_security_scan` — Package code, upload, start scan. Returns immediately with scan_id.
- `get_scan_status` — Check a previous scan's status (for session recovery)
- `get_scan_findings` — Get findings from a previously completed scan
- `list_scans` — List all tracked scans
- `stop_scan` — Cancel a running scan

### Remediation
- `start_remediation` — Generate code fixes for specific findings
- `get_remediation_diff` — Download generated fix diffs

## Workflow
1. Call `setup_check` to verify readiness
2. If not ready, call `setup` to provision resources
3. Call `start_security_scan(path=".")` — returns immediately with scan_id
4. Poll with `get_scan_status` until complete
5. Call `get_scan_findings` to retrieve results
6. Use `start_remediation` + `get_remediation_diff` to apply auto-generated fixes

## Important
- Scans take 15-30 minutes. Use `get_scan_status` to poll for completion.
- Always use `start_remediation`/`get_remediation_diff` for fixes — never edit code manually.
- Remediation mode AUTOMATIC generates fixes automatically during scan.
"""
