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

Comprehensive MCP server for AWS Security Agent — security scanning and penetration testing.

## Available Tools

### Setup
- `setup_check` — Verify prerequisites (credentials, agent space, role)
- `setup` — Create/reuse agent space and IAM service role

### Code Review (orchestrated)
- `start_security_scan` — Zip code, upload to S3, create code review, start scan. Returns scan_id.
- `get_scan_status` — Poll scan progress
- `get_scan_findings` — Get vulnerabilities found (includes remediation guidance and code locations)
- `list_scans` — List tracked scans
- `stop_scan` — Cancel a running scan

### Full API Access
- `call_api` — Call ANY SecurityAgent API operation (pentests, target domains, integrations, artifacts, etc.)
- `get_api_guide` — List all available operations with docs link

## Workflows

### Code Review (source scan)
1. `setup_check` → `setup` (one-time)
2. `start_security_scan(path=".")` → returns scan_id
3. Poll with `get_scan_status` until COMPLETED
4. `get_scan_findings` → view results with remediation guidance
5. Apply fixes based on `remediationCode` and `codeLocations` in findings

### Penetration Test
1. `setup_check` → `setup` (one-time)
2. `call_api("CreateTargetDomain", {agentSpaceId, domain})` → register target
3. `call_api("VerifyTargetDomain", {agentSpaceId, targetDomainId})` → verify ownership
4. `call_api("CreatePentest", {agentSpaceId, title, assets: {endpoints: [...]}})` → create pentest
5. `call_api("StartPentestJob", {agentSpaceId, pentestId})` → start
6. Poll with `call_api("BatchGetPentestJobs", ...)` until COMPLETED
7. `call_api("ListFindings", {agentSpaceId, codeReviewJobId})` → results

### Any Other Operation
1. `get_api_guide` → see all available operations
2. `call_api(operation, params)` → execute
"""
