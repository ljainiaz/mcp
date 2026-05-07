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

"""Integration tests for security-agent-mcp-server.

Mock-based integration tests that verify the full tool flow with realistic
mocked AWS responses, following the pattern used by cloudwatch-mcp-server
and lambda-tool-mcp-server.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


@pytest.fixture
def mock_context():
    """Create mock MCP context."""
    ctx = MagicMock()
    ctx.info = AsyncMock()
    ctx.warning = AsyncMock()
    ctx.error = AsyncMock()
    ctx.report_progress = AsyncMock()
    return ctx


class TestIntegSetupFlow:
    """Integration tests for the setup flow."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_full_setup_new_account(self, mock_client, mock_state, mock_context):
        """Test complete setup flow for a fresh account with no existing resources."""
        from awslabs.security_agent_mcp_server.server import setup, setup_check

        # 1. setup_check shows not ready
        mock_state.get_config.return_value = {}
        mock_client.get_caller_identity.return_value = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/dev',
        }

        result = await setup_check(mock_context)
        assert '"ready": false' in result
        assert 'agent_space_id' in result

        # 2. setup creates everything
        mock_client.list_agent_spaces.return_value = []
        mock_client.create_s3_bucket.return_value = 'security-agent-scans-123456789012-us-east-1'
        mock_client.create_service_role.return_value = (
            'arn:aws:iam::123456789012:role/SecurityAgentScanRole'
        )
        mock_client.create_agent_space.return_value = {'agentSpaceId': 'as-new-space-id'}
        mock_state.update_config = MagicMock()

        result = await setup(mock_context, name='my-scans', agent_space_id=None, use_existing_role=None)
        assert 'ready' in result
        assert 'as-new-space-id' in result
        mock_client.create_s3_bucket.assert_called_once()
        mock_client.create_service_role.assert_called_once()
        mock_client.create_agent_space.assert_called_once()

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_setup_existing_space_existing_role(self, mock_client, mock_state, mock_context):
        """Test setup reusing an existing agent space with a valid role."""
        from awslabs.security_agent_mcp_server.server import setup

        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.get_agent_space.return_value = {
            'name': 'existing-space',
            'awsResources': {
                'iamRoles': ['arn:aws:iam::123456789012:role/ExistingRole'],
                's3Buckets': ['existing-bucket'],
            },
        }
        mock_client.simulate_role_s3_permissions.return_value = True
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_client.update_agent_space.return_value = {}
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()

        result = await setup(
            mock_context, name='test', agent_space_id='as-existing', use_existing_role=True
        )
        assert 'ready' in result
        mock_client.simulate_role_s3_permissions.assert_called_once()


class TestIntegScanFlow:
    """Integration tests for the scan flow."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_full_scan_flow(self, mock_state, mock_scanner, mock_context):
        """Test complete scan: start returns immediately, then poll + get findings separately."""
        from awslabs.security_agent_mcp_server.server import (
            get_scan_findings,
            get_scan_status,
            start_security_scan,
        )

        mock_state.get_config.return_value = {
            'agent_space_id': 'as-123',
            'service_role': 'arn:aws:iam::123:role/Role',
            's3_bucket': 'scan-bucket',
        }

        # 1. Start scan — returns immediately
        mock_scanner.start_scan = AsyncMock(return_value={
            'scan_id': 'scan-abc123',
            'job_id': 'cj-def456',
            'status': 'STARTED',
        })

        result = await start_security_scan(
            mock_context, path='/app', title='pre-cr-main', remediation='AUTOMATIC'
        )
        assert 'scan-abc123' in result
        assert 'STARTED' in result
        mock_scanner.start_scan.assert_called_once()

        # 2. Poll status
        mock_scanner.get_status = AsyncMock(return_value={
            'status': 'COMPLETED',
            'steps': [
                {'name': 'PREFLIGHT', 'status': 'COMPLETED'},
                {'name': 'STATIC_ANALYSIS', 'status': 'COMPLETED'},
            ],
            'elapsed': '180s',
        })

        status_result = await get_scan_status(mock_context, scan_id='scan-abc123')
        assert 'COMPLETED' in status_result

        # 3. Get findings
        mock_scanner.get_findings = AsyncMock(return_value={
            'total_findings': 3,
            'findings': [
                {'findingId': 'f-1', 'title': 'SQL Injection', 'riskLevel': 'CRITICAL'},
                {'findingId': 'f-2', 'title': 'Hardcoded Credentials', 'riskLevel': 'HIGH'},
                {'findingId': 'f-3', 'title': 'Path Traversal', 'riskLevel': 'HIGH'},
            ],
        })

        findings_result = await get_scan_findings(mock_context, scan_id='scan-abc123')
        assert 'total_findings' in findings_result
        assert 'SQL Injection' in findings_result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_scan_not_configured(self, mock_state, mock_scanner, mock_context):
        """Test scan fails gracefully when not configured."""
        from awslabs.security_agent_mcp_server.server import start_security_scan

        mock_state.get_config.return_value = {'agent_space_id': 'as-1'}  # missing role and bucket

        result = await start_security_scan(
            mock_context, path='.', title='test', remediation='AUTOMATIC'
        )
        assert 'error' in result
        assert 'Not configured' in result


class TestIntegRemediationFlow:
    """Integration tests for the remediation flow."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_remediation_and_diff(self, mock_scanner, mock_context):
        """Test starting remediation and getting diff."""
        from awslabs.security_agent_mcp_server.server import get_remediation_diff, start_remediation

        # Start remediation
        mock_scanner.start_remediation = AsyncMock(return_value={
            'status': 'STARTED',
            'finding_ids': ['f-1', 'f-2'],
        })

        result = await start_remediation(
            mock_context, scan_id='scan-abc', finding_ids=['f-1', 'f-2']
        )
        assert 'STARTED' in result

        # Get diff
        mock_scanner.get_remediation_diff = AsyncMock(return_value={
            'diffs': [
                {
                    'finding_id': 'f-1',
                    'file_path': 'src/db/users.py',
                    'diff': '--- a/src/db/users.py\n+++ b/src/db/users.py\n@@ -42,3 +42,3 @@\n-    query = f"SELECT * FROM users WHERE id = {user_id}"\n+    query = "SELECT * FROM users WHERE id = %s"\n',
                },
            ],
        })

        result = await get_remediation_diff(mock_context, scan_id='scan-abc', finding_id='f-1')
        assert 'diffs' in result
        assert 'src/db/users.py' in result
