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

"""AWS Security Agent MCP Server implementation."""

import json
import os
import sys
from awslabs.security_agent_mcp_server.aws_client import SecurityAgentClient
from awslabs.security_agent_mcp_server.consts import (
    DEFAULT_REGION,
    SERVER_INSTRUCTIONS,
)
from awslabs.security_agent_mcp_server.scanner import Scanner
from awslabs.security_agent_mcp_server.state import StateManager
from loguru import logger
from mcp.server.fastmcp import Context, FastMCP
from pydantic import Field
from typing import List, Literal, Optional


# Configure logging
logger.remove()
logger.add(sys.stderr, level=os.getenv('FASTMCP_LOG_LEVEL', 'WARNING'))

# Initialize MCP server
mcp = FastMCP(
    'awslabs.security-agent-mcp-server',
    instructions=SERVER_INSTRUCTIONS,
    dependencies=['boto3', 'gitignorefile', 'pydantic', 'loguru'],
)

# Initialize components
_region = os.environ.get('AWS_REGION', DEFAULT_REGION)

_client = SecurityAgentClient(region=_region)
_state = StateManager(region=_region)
_scanner = Scanner(client=_client, state=_state)


@mcp.tool()
async def setup_check(ctx: Context) -> str:
    """Check if AWS Security Agent prerequisites are configured.

    Verifies that agent space, service role, S3 bucket, and AWS credentials are available.
    Call this before starting a scan to ensure everything is ready.
    """
    try:
        config = _state.get_config()
        missing = []

        if not config.get('agent_space_id'):
            missing.append('agent_space_id')
        if not config.get('service_role'):
            missing.append('service_role')
        if not config.get('s3_bucket'):
            missing.append('s3_bucket')

        try:
            _client.get_caller_identity()
        except Exception as e:
            missing.append(f'aws_credentials ({e})')

        result = {'ready': len(missing) == 0, 'missing': missing, 'config': config}
        logger.info(f'Setup check: ready={result["ready"]}')
        return json.dumps(result)
    except Exception as e:
        logger.error(f'Error in setup_check: {e}')
        await ctx.error(f'Error checking setup: {e}')
        raise


@mcp.tool()
async def setup(
    ctx: Context,
    name: str = Field(
        default='security-scans',
        description='Name for the agent space if creating a new one.',
    ),
    agent_space_id: Optional[str] = Field(
        default=None,
        description='Existing agent space ID to use. If not provided, lists existing spaces or creates new.',
    ),
    use_existing_role: Optional[bool] = Field(
        default=None,
        description='Whether to use an existing IAM role on the agent space. None=ask, True=validate and use, False=create new.',
    ),
) -> str:
    """One-time setup: provision or reuse agent space, S3 bucket, and IAM service role.

    ## Workflow
    1. If no agent_space_id: lists existing spaces for user selection, or creates new
    2. Creates S3 bucket for code uploads if needed
    3. Creates or validates IAM service role with SecurityAgent trust policy
    4. Registers role and bucket on the agent space

    ## Multi-step
    This tool may return intermediate status requiring user input:
    - `needs_agent_space_selection`: existing spaces found, pick one or create new
    - `needs_role_selection`: existing role found on space, use it or create new
    - `role_missing_permissions`: selected role lacks required S3 permissions
    """
    try:
        identity = _client.get_caller_identity()
        account_id = identity['Account']
        config = _state.get_config()

        # 1. Resolve agent space
        if not agent_space_id:
            agent_space_id = config.get('agent_space_id')

        if not agent_space_id:
            spaces = _client.list_agent_spaces()
            if spaces and name == 'security-scans':
                return json.dumps(
                    {
                        'status': 'needs_agent_space_selection',
                        'message': 'Found existing agent spaces. Pick one or create new.',
                        'spaces': [
                            {'id': s.get('agentSpaceId'), 'name': s.get('name')} for s in spaces
                        ],
                        'hint': "Call setup(agent_space_id='...') with your choice, or setup(name='my-new-space') to create new.",
                    }
                )

        # 2. Create S3 bucket if needed
        s3_bucket = config.get('s3_bucket')
        if not s3_bucket:
            s3_bucket = f'security-agent-scans-{account_id}-{_region}'
            try:
                _client.create_s3_bucket(s3_bucket)
                logger.info(f'Created S3 bucket: {s3_bucket}')
            except Exception as e:
                if 'BucketAlreadyOwnedByYou' not in str(e):
                    raise
            _state.update_config(s3_bucket=s3_bucket)

        # 3. Resolve service role
        service_role = config.get('service_role')
        space_details = None
        if not service_role:
            if agent_space_id:
                space_details = _client.get_agent_space(agent_space_id)
                existing_roles = space_details.get('awsResources', {}).get('iamRoles', [])

                if existing_roles and use_existing_role is None:
                    return json.dumps(
                        {
                            'status': 'needs_role_selection',
                            'agent_space_id': agent_space_id,
                            'existing_roles': existing_roles,
                            'message': 'This agent space has existing role(s). Use existing or create new?',
                            'hint': "Call setup(agent_space_id='...', use_existing_role=True) or setup(agent_space_id='...', use_existing_role=False)",
                        }
                    )

                if use_existing_role and existing_roles:
                    candidate_role = existing_roles[0]
                    has_s3 = _client.simulate_role_s3_permissions(candidate_role, s3_bucket)
                    if has_s3:
                        service_role = candidate_role
                        _state.update_config(service_role=service_role)
                    else:
                        return json.dumps(
                            {
                                'status': 'role_missing_permissions',
                                'role': candidate_role,
                                'message': f"Role lacks S3 permissions on '{s3_bucket}'.",
                                'hint': "Call setup(agent_space_id='...', use_existing_role=False) to create new.",
                            }
                        )

            if not service_role:
                role_name = 'SecurityAgentScanRole'
                try:
                    service_role = _client.create_service_role(role_name, account_id, s3_bucket)
                    logger.info(f'Created service role: {service_role}')
                except Exception as e:
                    if 'EntityAlreadyExists' in str(e):
                        service_role = f'arn:aws:iam::{account_id}:role/{role_name}'
                    else:
                        raise
                _state.update_config(service_role=service_role)

        # 4. Create or update agent space
        if not agent_space_id:
            result = _client.create_agent_space(
                name=name, service_role=service_role, s3_bucket=s3_bucket
            )
            agent_space_id = result['agentSpaceId']
            logger.info(f'Created agent space: {agent_space_id}')
        else:
            if not space_details:
                space_details = _client.get_agent_space(agent_space_id)
            space_name = space_details.get('name', name)
            existing_roles = space_details.get('awsResources', {}).get('iamRoles', [])
            existing_buckets = space_details.get('awsResources', {}).get('s3Buckets', [])

            needs_update = False
            if service_role not in existing_roles:
                existing_roles.append(service_role)
                needs_update = True
            if s3_bucket not in existing_buckets:
                existing_buckets.append(s3_bucket)
                needs_update = True

            if needs_update:
                _client.update_agent_space(
                    agent_space_id, space_name, existing_roles, existing_buckets
                )

        _state.update_config(agent_space_id=agent_space_id)

        return json.dumps(
            {
                'status': 'ready',
                'agent_space_id': agent_space_id,
                's3_bucket': s3_bucket,
                'service_role': service_role,
                'account_id': account_id,
            }
        )
    except Exception as e:
        logger.error(f'Error in setup: {e}')
        await ctx.error(f'Setup failed: {e}')
        raise


@mcp.tool()
async def start_security_scan(
    ctx: Context,
    path: str = Field(
        default='.',
        description='Path to the code directory to scan. CRITICAL: Assistant must provide the current workspace directory.',
    ),
    title: Optional[str] = Field(
        default=None,
        description='Title for the scan. Defaults to auto-generated name with timestamp.',
    ),
    remediation: Literal['AUTOMATIC', 'DISABLED'] = Field(
        default='AUTOMATIC',
        description="Remediation mode. 'AUTOMATIC' generates fixes during scan. 'DISABLED' skips fix generation.",
    ),
) -> str:
    """Start a security code review scan. Zips code, uploads to S3, starts scan, returns immediately.

    Returns scan_id for polling with get_scan_status. The scan runs server-side
    and typically takes 15-30 minutes. Use get_scan_status to check progress
    and get_scan_findings to retrieve results when complete.
    """
    try:
        config = _state.get_config()
        if (
            not config.get('agent_space_id')
            or not config.get('service_role')
            or not config.get('s3_bucket')
        ):
            return json.dumps({'error': 'Not configured. Run setup_check first.'})

        logger.info(f'Starting security scan on path: {path}')
        result = await _scanner.start_scan(path=path, title=title, remediation=remediation)
        return json.dumps(result)
    except Exception as e:
        logger.error(f'Error in start_security_scan: {e}')
        await ctx.error(f'Scan failed: {e}')
        raise


@mcp.tool()
async def get_scan_status(
    ctx: Context,
    scan_id: Optional[str] = Field(
        default=None,
        description='Scan ID to check. Uses the most recent scan if not provided.',
    ),
) -> str:
    """Check the status of a security scan.

    Useful for checking a previous scan from an earlier session, or verifying
    a scan completed after session recovery.
    """
    try:
        return json.dumps(await _scanner.get_status(scan_id=scan_id))
    except Exception as e:
        logger.error(f'Error in get_scan_status: {e}')
        await ctx.error(f'Error checking status: {e}')
        raise


@mcp.tool()
async def get_scan_findings(
    ctx: Context,
    scan_id: Optional[str] = Field(
        default=None,
        description='Scan ID to get findings for. Uses the most recent scan if not provided.',
    ),
    severity: Optional[str] = Field(
        default=None,
        description='Filter findings by minimum severity: CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL.',
    ),
) -> str:
    """Get findings from a completed security scan.

    Returns findings with title, severity, confidence, file location, and description.
    """
    try:
        return json.dumps(await _scanner.get_findings(scan_id=scan_id, severity=severity))
    except Exception as e:
        logger.error(f'Error in get_scan_findings: {e}')
        await ctx.error(f'Error getting findings: {e}')
        raise


@mcp.tool()
async def list_scans(ctx: Context) -> str:
    """List all recent security scans tracked locally with their status."""
    try:
        return json.dumps({'scans': _state.list_scans()})
    except Exception as e:
        logger.error(f'Error in list_scans: {e}')
        await ctx.error(f'Error listing scans: {e}')
        raise


@mcp.tool()
async def stop_scan(
    ctx: Context,
    scan_id: str = Field(..., description='The scan ID to stop.'),
) -> str:
    """Stop a running security scan."""
    try:
        logger.info(f'Stopping scan: {scan_id}')
        return json.dumps(await _scanner.stop_scan(scan_id=scan_id))
    except Exception as e:
        logger.error(f'Error in stop_scan: {e}')
        await ctx.error(f'Error stopping scan: {e}')
        raise


@mcp.tool()
async def start_remediation(
    ctx: Context,
    scan_id: Optional[str] = Field(
        default=None,
        description='Scan ID containing the findings. Uses the most recent scan if not provided.',
    ),
    finding_ids: Optional[List[str]] = Field(
        default=None,
        description='List of finding IDs to generate fixes for. If not provided, remediates all findings.',
    ),
) -> str:
    """Start code remediation (fix generation) for specific findings.

    This triggers the SecurityAgent to generate code fixes for the specified vulnerabilities.
    After completion, use `get_remediation_diff` to download the generated patches.
    """
    try:
        logger.info(f'Starting remediation for scan={scan_id}, findings={finding_ids}')
        return json.dumps(await _scanner.start_remediation(scan_id=scan_id, finding_ids=finding_ids))
    except Exception as e:
        logger.error(f'Error in start_remediation: {e}')
        await ctx.error(f'Error starting remediation: {e}')
        raise


@mcp.tool()
async def get_remediation_diff(
    ctx: Context,
    scan_id: Optional[str] = Field(
        default=None,
        description='Scan ID to get remediation diff from. Uses the most recent scan if not provided.',
    ),
    finding_id: Optional[str] = Field(
        default=None,
        description='Specific finding ID to get the diff for. If not provided, returns all available diffs.',
    ),
) -> str:
    """Get the code fix diff for remediated findings.

    Returns unified diff content that can be applied to the local workspace.
    The diff is generated by the SecurityAgent based on the vulnerability context.
    """
    try:
        return json.dumps(await _scanner.get_remediation_diff(scan_id=scan_id, finding_id=finding_id))
    except Exception as e:
        logger.error(f'Error in get_remediation_diff: {e}')
        await ctx.error(f'Error getting remediation diff: {e}')
        raise


def main():
    """Run the MCP server with CLI argument support."""
    mcp.run()


if __name__ == '__main__':
    main()
