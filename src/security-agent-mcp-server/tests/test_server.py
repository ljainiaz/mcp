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

"""Tests for the MCP server tools."""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from awslabs.security_agent_mcp_server.server import mcp


def test_server_has_expected_tools():
    """Verify all expected tools are registered."""
    tools = mcp._tool_manager._tools
    expected = {
        'setup_check',
        'setup',
        'start_security_scan',
        'get_scan_status',
        'get_scan_findings',
        'list_scans',
        'stop_scan',
        'start_remediation',
        'get_remediation_diff',
    }
    assert set(tools.keys()) == expected


def test_server_name():
    """Verify server name is correct."""
    assert mcp.name == 'awslabs.security-agent-mcp-server'


def test_server_has_instructions():
    """Verify server has instructions set."""
    assert mcp.instructions is not None
    assert 'AWS Security Agent' in mcp.instructions


def test_server_tool_count():
    """Verify correct number of tools."""
    assert len(mcp._tool_manager._tools) == 9


class TestSetupCheck:
    """Tests for setup_check tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_ready(self, mock_client, mock_state):
        """Returns ready when all configured."""
        mock_state.get_config.return_value = {
            'agent_space_id': 'as-1',
            'service_role': 'arn:role',
            's3_bucket': 'bucket',
        }
        mock_client.get_caller_identity.return_value = {'Account': '123'}
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup_check

        result = await setup_check(ctx)
        assert 'true' in result or '"ready": true' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_not_ready(self, mock_client, mock_state):
        """Returns missing items when not configured."""
        mock_state.get_config.return_value = {}
        mock_client.get_caller_identity.return_value = {'Account': '123'}
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup_check

        result = await setup_check(ctx)
        assert 'false' in result or '"ready": false' in result
        assert 'agent_space_id' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_creds_error(self, mock_client, mock_state):
        """Reports credential error."""
        mock_state.get_config.return_value = {
            'agent_space_id': 'as-1',
            'service_role': 'arn:role',
            's3_bucket': 'bucket',
        }
        mock_client.get_caller_identity.side_effect = Exception('no creds')
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup_check

        result = await setup_check(ctx)
        assert 'aws_credentials' in result


class TestSetup:
    """Tests for setup tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_needs_space_selection(self, mock_client, mock_state):
        """Returns space selection when spaces exist."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.list_agent_spaces.return_value = [
            {'agentSpaceId': 'as-1', 'name': 'space-1'}
        ]
        mock_state.get_config.return_value = {}
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='security-scans', agent_space_id=None, use_existing_role=None)
        assert 'needs_agent_space_selection' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_creates_all_resources(self, mock_client, mock_state):
        """Creates bucket, role, and space when nothing exists."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.list_agent_spaces.return_value = []
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_client.create_service_role.return_value = 'arn:aws:iam::123456789012:role/SecurityAgentScanRole'
        mock_client.create_agent_space.return_value = {'agentSpaceId': 'as-new'}
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='test', agent_space_id=None, use_existing_role=None)
        assert 'ready' in result
        assert 'as-new' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_uses_existing_space(self, mock_client, mock_state):
        """Uses existing space and updates it."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.get_agent_space.return_value = {
            'name': 'existing',
            'awsResources': {'iamRoles': [], 's3Buckets': []},
        }
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_client.create_service_role.return_value = 'arn:aws:iam::123456789012:role/R'
        mock_client.update_agent_space.return_value = {}
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='test', agent_space_id='as-exist', use_existing_role=False)
        assert 'ready' in result
        mock_client.update_agent_space.assert_called_once()

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_needs_role_selection(self, mock_client, mock_state):
        """Returns role selection when existing roles found."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.get_agent_space.return_value = {
            'name': 'space',
            'awsResources': {'iamRoles': ['arn:aws:iam::123:role/Existing'], 's3Buckets': []},
        }
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='test', agent_space_id='as-1', use_existing_role=None)
        assert 'needs_role_selection' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_existing_role_valid(self, mock_client, mock_state):
        """Uses existing role when it has permissions."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.get_agent_space.return_value = {
            'name': 'space',
            'awsResources': {'iamRoles': ['arn:aws:iam::123:role/Good'], 's3Buckets': ['bucket']},
        }
        mock_client.simulate_role_s3_permissions.return_value = True
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_client.update_agent_space.return_value = {}
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='test', agent_space_id='as-1', use_existing_role=True)
        assert 'ready' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    @patch('awslabs.security_agent_mcp_server.server._client')
    async def test_existing_role_missing_perms(self, mock_client, mock_state):
        """Returns error when existing role lacks permissions."""
        mock_client.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_client.get_agent_space.return_value = {
            'name': 'space',
            'awsResources': {'iamRoles': ['arn:aws:iam::123:role/Bad'], 's3Buckets': []},
        }
        mock_client.simulate_role_s3_permissions.return_value = False
        mock_client.create_s3_bucket.return_value = 'bucket'
        mock_state.get_config.return_value = {}
        mock_state.update_config = MagicMock()
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import setup

        result = await setup(ctx, name='test', agent_space_id='as-1', use_existing_role=True)
        assert 'role_missing_permissions' in result


class TestListScans:
    """Tests for list_scans tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_list_scans_empty(self, mock_state):
        """Returns empty list when no scans."""
        mock_state.list_scans.return_value = []
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import list_scans

        result = await list_scans(ctx)
        assert '[]' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_list_scans_with_data(self, mock_state):
        """Returns scans list."""
        mock_state.list_scans.return_value = [
            {'scan_id': 'scan-1', 'status': 'COMPLETED'}
        ]
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import list_scans

        result = await list_scans(ctx)
        assert 'scan-1' in result


class TestGetScanStatus:
    """Tests for get_scan_status tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_returns_status(self, mock_scanner):
        """Returns scan status."""
        mock_scanner.get_status = AsyncMock(return_value={'status': 'COMPLETED', 'elapsed': '300s'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import get_scan_status

        result = await get_scan_status(ctx, scan_id='scan-1')
        assert 'COMPLETED' in result


class TestGetScanFindings:
    """Tests for get_scan_findings tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_returns_findings(self, mock_scanner):
        """Returns findings."""
        mock_scanner.get_findings = AsyncMock(return_value={
            'total_findings': 2,
            'findings': [{'title': 'XSS'}, {'title': 'SQLi'}],
        })
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import get_scan_findings

        result = await get_scan_findings(ctx, scan_id='scan-1')
        assert 'XSS' in result
        assert 'SQLi' in result


class TestStopScan:
    """Tests for stop_scan tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_stops_scan(self, mock_scanner):
        """Stops a scan."""
        mock_scanner.stop_scan = AsyncMock(return_value={'scan_id': 'scan-1', 'status': 'STOPPED'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import stop_scan

        result = await stop_scan(ctx, scan_id='scan-1')
        assert 'STOPPED' in result


class TestStartSecurityScan:
    """Tests for start_security_scan tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_not_configured(self, mock_state, mock_scanner):
        """Returns error when not configured."""
        mock_state.get_config.return_value = {}
        ctx = MagicMock()
        ctx.error = AsyncMock()
        ctx.report_progress = AsyncMock()
        ctx.info = AsyncMock()

        from awslabs.security_agent_mcp_server.server import start_security_scan

        result = await start_security_scan(ctx, path='.', title=None, remediation='AUTOMATIC')
        assert 'error' in result
        assert 'Not configured' in result

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_scan_completes(self, mock_state, mock_scanner):
        """Returns scan_id immediately."""
        mock_state.get_config.return_value = {
            'agent_space_id': 'as-1',
            'service_role': 'role',
            's3_bucket': 'bucket',
        }
        mock_scanner.start_scan = AsyncMock(return_value={'scan_id': 'scan-1', 'job_id': 'cj-1', 'status': 'STARTED'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import start_security_scan

        result = await start_security_scan(ctx, path='.', title='test', remediation='AUTOMATIC')
        assert 'scan-1' in result
        assert 'STARTED' in result
        mock_scanner.start_scan.assert_called_once()

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    @patch('awslabs.security_agent_mcp_server.server._state')
    async def test_scan_start_error_from_scanner(self, mock_state, mock_scanner):
        """Returns error when scanner fails."""
        mock_state.get_config.return_value = {
            'agent_space_id': 'as-1',
            'service_role': 'role',
            's3_bucket': 'bucket',
        }
        mock_scanner.start_scan = AsyncMock(return_value={'error': 'zip failed'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import start_security_scan

        result = await start_security_scan(ctx, path='.', title='test', remediation='AUTOMATIC')
        assert 'error' in result

class TestStartRemediation:
    """Tests for start_remediation tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_starts_remediation(self, mock_scanner):
        """Starts remediation."""
        mock_scanner.start_remediation = AsyncMock(return_value={'status': 'STARTED'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import start_remediation

        result = await start_remediation(ctx, scan_id='scan-1', finding_ids=['f-1'])
        assert 'STARTED' in result


class TestGetRemediationDiff:
    """Tests for get_remediation_diff tool."""

    @pytest.mark.asyncio
    @patch('awslabs.security_agent_mcp_server.server._scanner')
    async def test_gets_diff(self, mock_scanner):
        """Gets remediation diff."""
        mock_scanner.get_remediation_diff = AsyncMock(return_value={'diff': '--- a\n+++ b'})
        ctx = MagicMock()
        ctx.error = AsyncMock()

        from awslabs.security_agent_mcp_server.server import get_remediation_diff

        result = await get_remediation_diff(ctx, scan_id='scan-1', finding_id='f-1')
        assert 'diff' in result
