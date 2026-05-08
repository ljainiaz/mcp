# AWS Security Agent MCP Server

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An AWS Labs Model Context Protocol (MCP) server for **AWS Security Agent** — automated security scanning, penetration testing, and remediation.

This MCP server provides full access to the AWS Security Agent service, enabling developers to scan source code for vulnerabilities, run penetration tests against live applications, manage integrations, and apply auto-generated fixes — all from any MCP-compatible client.

## Features

- **Code security scanning** — zip, upload, scan source code, get findings with fixes
- **Penetration testing** — test live applications via target domains
- **Full API access** — `call_api` tool exposes all SecurityAgent operations
- **Auto-provisioning** — creates agent space and IAM service role on first use
- **Code remediation** — auto-generates fixes for vulnerabilities, returns diffs
- **Respects .gitignore** — excludes ignored files from packaging

## Prerequisites

1. [uv](https://docs.astral.sh/uv/getting-started/installation/) installed
2. Python 3.10+ (`uv python install 3.10`)
3. AWS credentials configured (via `aws configure`, SSO, or environment variables)

## Installation

### Using uvx (recommended)

```json
{
  "mcpServers": {
    "awslabs.security-agent-mcp-server": {
      "command": "uvx",
      "args": ["awslabs.security-agent-mcp-server@latest"],
      "env": {
        "AWS_PROFILE": "default",
        "AWS_REGION": "us-east-1",
        "FASTMCP_LOG_LEVEL": "ERROR"
      }
    }
  }
}
```

### Using Docker

```json
{
  "mcpServers": {
    "awslabs.security-agent-mcp-server": {
      "command": "docker",
      "args": [
        "run", "-i", "--rm",
        "-e", "AWS_REGION=us-east-1",
        "-e", "AWS_ACCESS_KEY_ID",
        "-e", "AWS_SECRET_ACCESS_KEY",
        "-e", "AWS_SESSION_TOKEN",
        "awslabs/security-agent-mcp-server:latest"
      ]
    }
  }
}
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for SecurityAgent API calls | `us-east-1` |
| `AWS_PROFILE` | AWS credential profile name | default profile |
| `FASTMCP_LOG_LEVEL` | Log level (DEBUG, INFO, WARNING, ERROR) | `WARNING` |

### Available Regions

See [AWS documentation](https://docs.aws.amazon.com/securityagent/latest/userguide/resilience.html) for available regions.

## Available Tools

### Setup

| Tool | Description |
|------|-------------|
| `setup_check` | Verify prerequisites — credentials, agent space, role |
| `setup` | Create/reuse agent space and IAM service role |

### Code Review (orchestrated)

| Tool | Description |
|------|-------------|
| `start_security_scan` | Zip code, upload to S3, create review, start scan. Returns scan_id. |
| `get_scan_status` | Poll scan progress |
| `get_scan_findings` | Get findings from completed scan |
| `list_scans` | List tracked scans |
| `stop_scan` | Cancel a running scan |

### Remediation

| Tool | Description |
|------|-------------|
| `start_remediation` | Generate code fixes for findings |
| `get_remediation_diff` | Download fix diffs to apply locally |

### Full API Access

| Tool | Description |
|------|-------------|
| `call_api` | Call any SecurityAgent API operation (pentests, target domains, integrations, artifacts, etc.) |
| `get_api_guide` | List all available operations dynamically + documentation link |

## Usage Flows

### Code Review (source scan)

```
1. setup_check()              → verify readiness
2. setup()                    → provision resources (one-time)
3. start_security_scan(path=".", remediation="AUTOMATIC")
4. get_scan_status()          → poll until COMPLETED
5. get_scan_findings()        → retrieve findings
6. get_remediation_diff()     → download code fixes
```

### Penetration Test

```
1. setup_check() → setup()   → one-time
2. call_api("CreateTargetDomain", {agentSpaceId, domain})
3. call_api("VerifyTargetDomain", {agentSpaceId, targetDomainId})
4. call_api("CreatePentest", {agentSpaceId, title, assets: {endpoints: [...]}})
5. call_api("StartPentestJob", {agentSpaceId, pentestId})
6. Poll: call_api("BatchGetPentestJobs", {agentSpaceId, pentestJobIds})
7. call_api("ListFindings", {agentSpaceId, codeReviewJobId})
```

### Any Operation

```
1. get_api_guide()            → see all operations + docs link
2. call_api(operation, params) → execute
```

## Required IAM Permissions

These permissions are needed on **your AWS credentials** (the identity running the MCP server):

### For setup (one-time)
- `iam:CreateRole`, `iam:PutRolePolicy` (if creating a new service role)
- `s3:CreateBucket`, `s3:PutPublicAccessBlock`, `s3:PutLifecycleConfiguration` (if creating a new bucket)
- `sts:GetCallerIdentity`
- `securityagent:CreateAgentSpace`, `securityagent:UpdateAgentSpace`
- `securityagent:ListAgentSpaces`, `securityagent:BatchGetAgentSpaces`

### For code scanning
- `s3:PutObject`
- `securityagent:CreateCodeReview`, `securityagent:StartCodeReviewJob`
- `securityagent:BatchGetCodeReviewJobs`, `securityagent:StopCodeReviewJob`
- `securityagent:ListFindings`, `securityagent:BatchGetFindings`
- `securityagent:StartCodeRemediation`, `securityagent:BatchDeleteCodeReviews`

### For pentesting and other operations

Add SecurityAgent permissions as needed for your use case. See [How AWS Security Agent works with IAM](https://docs.aws.amazon.com/securityagent/latest/userguide/security_iam_service-with-iam.html) for details on available actions.

## Service Role

During setup, the server creates an IAM service role `SecurityAgentScanRole` (if one doesn't already exist). If an existing role is found on the agent space, it can be reused after validating its permissions.

The service role is assumed by the SecurityAgent service to read your uploaded code:

- **Trust policy**: `securityagent.amazonaws.com` service principal
- **Permissions**: S3 read on scan bucket, CloudWatch Logs write

> **Note**: An S3 bucket is used to temporarily store source code for scanning. The MCP server sets a 30-day lifecycle policy on buckets it creates — uploaded content is automatically deleted. If you use your own bucket, consider adding a lifecycle rule to manage storage costs.

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

Apache-2.0. See [LICENSE](LICENSE).
