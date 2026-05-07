# AWS Security Agent MCP Server

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-yellow.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)

An AWS Labs Model Context Protocol (MCP) server for **AWS Security Agent** — run automated security code reviews before publishing CRs.

This MCP server enables developers to scan source code for security vulnerabilities directly from their IDE using Amazon Security Agent's CodeScannerAgent. It packages local code, uploads to S3, triggers a scan, and returns findings with auto-generated fixes.

## Features

- **One-command security scanning** — zip, upload, start scan, returns immediately with scan_id
- **Auto-provisioning** — creates agent space, S3 bucket, and IAM service role on first use
- **Reuse existing resources** — detects and validates existing agent spaces and roles
- **Code remediation** — auto-generates fixes for vulnerabilities, returns diffs
- **Progress reporting** — MCP progress notifications during scan execution
- **Respects .gitignore** — only packages tracked files

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

AWS Security Agent is available in: `us-east-1`, `us-west-2`, `eu-west-1`, `eu-central-1`, `ap-southeast-2`, `ap-northeast-1`.

To change the region, edit `AWS_REGION` in your MCP configuration:

```json
"env": {
  "AWS_REGION": "us-west-2"
}
```

## Available Tools

### Setup (one-time)

| Tool | Description |
|------|-------------|
| `setup_check` | Verify prerequisites — credentials, agent space, role, bucket |
| `setup` | Auto-provision or reuse resources with interactive flow |

### Scanning

| Tool | Description |
|------|-------------|
| `start_security_scan` | Package code, upload, start scan. **Returns immediately.** |
| `get_scan_status` | Check status of a previous scan (session recovery) |
| `get_scan_findings` | Get findings from a previously completed scan |
| `list_scans` | List all tracked scans |
| `stop_scan` | Cancel a running scan |

### Remediation

| Tool | Description |
|------|-------------|
| `start_remediation` | Generate code fixes for specific finding IDs |
| `get_remediation_diff` | Download generated fix diffs to apply locally |

## Usage Flow

```
1. setup_check()              → verify readiness
2. setup()                    → provision resources (interactive, one-time)
3. start_security_scan(       → returns immediately with scan_id
     path=".",
     remediation="AUTOMATIC"
   )
4. get_scan_status()          → poll until COMPLETED (15-30 min)
5. get_scan_findings()        → retrieve findings
6. get_remediation_diff()     → download auto-generated code fixes
7. Apply diffs locally
```

## Required IAM Permissions

### For setup (one-time)
- `iam:CreateRole`, `iam:PutRolePolicy`
- `s3:CreateBucket`, `s3:PutPublicAccessBlock`
- `securityagent:CreateAgentSpace`, `securityagent:UpdateAgentSpace`
- `securityagent:ListAgentSpaces`, `securityagent:GetAgentSpace`
- `iam:SimulatePrincipalPolicy`

### For scanning (ongoing)
- `securityagent:CreateCodeReview`, `securityagent:StartCodeReviewJob`
- `securityagent:BatchGetCodeReviewJobs`, `securityagent:ListFindings`
- `securityagent:BatchGetFindings`, `securityagent:StartCodeRemediation`
- `s3:PutObject`

## Service Role

The server creates an IAM role `SecurityAgentScanRole` with:

- **Trust policy**: `securityagent.amazonaws.com` service principal
- **Permissions**: S3 read on scan bucket, CloudWatch Logs write

## Contributing

See [CONTRIBUTING.md](../../CONTRIBUTING.md) for guidelines.

## License

Apache-2.0. See [LICENSE](LICENSE).
