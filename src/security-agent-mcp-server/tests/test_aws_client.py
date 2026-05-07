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

"""Tests for SecurityAgentClient."""

import json
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from awslabs.security_agent_mcp_server.aws_client import SecurityAgentClient


class TestSecurityAgentClientInit:
    """Tests for client initialization."""

    def test_prod_endpoint(self):
        """Initializes with prod endpoint."""
        client = SecurityAgentClient(region='us-east-1')
        assert 'securityagent.us-east-1.api.aws' in client.endpoint

    def test_default_endpoint(self):
        """Uses prod endpoint by default."""
        client = SecurityAgentClient(region='us-east-1')
        assert 'securityagent.us-east-1.api.aws' in client.endpoint


class TestSecurityAgentClientCall:
    """Tests for _call method."""

    @patch('awslabs.security_agent_mcp_server.aws_client.urllib.request.urlopen')
    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_call_success(self, mock_session, mock_urlopen):
        """Makes successful API call."""
        mock_creds = MagicMock()
        mock_creds.access_key = 'AKIA'
        mock_creds.secret_key = 'secret'
        mock_creds.token = 'token'
        mock_session.return_value.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds

        mock_response = MagicMock()
        mock_response.read.return_value = json.dumps({'result': 'ok'}).encode()
        mock_response.__enter__ = lambda s: s
        mock_response.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_response

        client = SecurityAgentClient(region='us-east-1')
        result = client._call('TestOp', {'key': 'value'})
        assert result == {'result': 'ok'}

    @patch('awslabs.security_agent_mcp_server.aws_client.urllib.request.urlopen')
    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_call_http_error(self, mock_session, mock_urlopen):
        """Raises RuntimeError on HTTP error."""
        mock_creds = MagicMock()
        mock_creds.access_key = 'AKIA'
        mock_creds.secret_key = 'secret'
        mock_creds.token = 'token'
        mock_session.return_value.get_credentials.return_value.get_frozen_credentials.return_value = mock_creds

        error = urllib.error.HTTPError(
            url='http://test', code=400, msg='Bad Request', hdrs={}, fp=None
        )
        mock_urlopen.side_effect = error

        client = SecurityAgentClient(region='us-east-1')
        with pytest.raises(RuntimeError, match='TestOp failed'):
            client._call('TestOp', {})


class TestSecurityAgentClientMethods:
    """Tests for individual client methods."""

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_get_caller_identity(self, mock_session):
        """Gets caller identity."""
        mock_sts = MagicMock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        mock_session.return_value.client.return_value = mock_sts
        client = SecurityAgentClient(region='us-east-1')
        assert client.get_caller_identity()['Account'] == '123456789012'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_list_agent_spaces(self, mock_call):
        """Lists agent spaces."""
        mock_call.return_value = {'agentSpaceSummaries': [{'agentSpaceId': 'as-1'}]}
        client = SecurityAgentClient(region='us-east-1')
        result = client.list_agent_spaces()
        assert len(result) == 1
        mock_call.assert_called_once_with('ListAgentSpaces', {})

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_get_agent_space(self, mock_call):
        """Gets agent space details."""
        mock_call.return_value = {'agentSpaces': [{'agentSpaceId': 'as-1', 'name': 'test'}]}
        client = SecurityAgentClient(region='us-east-1')
        result = client.get_agent_space('as-1')
        assert result['name'] == 'test'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_get_agent_space_empty(self, mock_call):
        """Returns empty dict when space not found."""
        mock_call.return_value = {'agentSpaces': []}
        client = SecurityAgentClient(region='us-east-1')
        assert client.get_agent_space('as-nope') == {}

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_update_agent_space(self, mock_call):
        """Updates agent space."""
        mock_call.return_value = {}
        client = SecurityAgentClient(region='us-east-1')
        client.update_agent_space('as-1', 'name', ['role-arn'], ['bucket'])
        call_body = mock_call.call_args[0][1]
        assert call_body['awsResources']['iamRoles'] == ['role-arn']
        assert call_body['awsResources']['s3Buckets'] == ['bucket']

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_simulate_role_s3_permissions_allowed(self, mock_session):
        """Returns True when role has S3 permissions."""
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            'EvaluationResults': [
                {'EvalDecision': 'allowed'},
                {'EvalDecision': 'allowed'},
            ]
        }
        mock_session.return_value.client.return_value = mock_iam
        client = SecurityAgentClient(region='us-east-1')
        assert client.simulate_role_s3_permissions('arn:aws:iam::123:role/R', 'bucket') is True

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_simulate_role_s3_permissions_denied(self, mock_session):
        """Returns False when role lacks S3 permissions."""
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.return_value = {
            'EvaluationResults': [{'EvalDecision': 'implicitDeny'}]
        }
        mock_session.return_value.client.return_value = mock_iam
        client = SecurityAgentClient(region='us-east-1')
        assert client.simulate_role_s3_permissions('arn:aws:iam::123:role/R', 'bucket') is False

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_simulate_role_s3_permissions_exception(self, mock_session):
        """Returns False on exception."""
        mock_iam = MagicMock()
        mock_iam.simulate_principal_policy.side_effect = Exception('access denied')
        mock_session.return_value.client.return_value = mock_iam
        client = SecurityAgentClient(region='us-east-1')
        assert client.simulate_role_s3_permissions('arn', 'bucket') is False

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_create_agent_space(self, mock_call):
        """Creates agent space with resources."""
        mock_call.return_value = {'agentSpaceId': 'as-new'}
        client = SecurityAgentClient(region='us-east-1')
        result = client.create_agent_space('my-space', 'role-arn', 'bucket')
        body = mock_call.call_args[0][1]
        assert body['name'] == 'my-space'
        assert body['awsResources']['iamRoles'] == ['role-arn']

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_create_s3_bucket_us_east_1(self, mock_session):
        """Creates bucket without LocationConstraint in us-east-1."""
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        client = SecurityAgentClient(region='us-east-1')
        client.create_s3_bucket('my-bucket')
        call_args = mock_s3.create_bucket.call_args
        assert 'CreateBucketConfiguration' not in call_args.kwargs.get('CreateBucketConfiguration', call_args[1] if len(call_args) > 1 else {})

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_create_s3_bucket_other_region(self, mock_session):
        """Creates bucket with LocationConstraint in non-us-east-1."""
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        client = SecurityAgentClient(region='us-west-2')
        client.create_s3_bucket('my-bucket')
        call_kwargs = mock_s3.create_bucket.call_args[1]
        assert call_kwargs['CreateBucketConfiguration']['LocationConstraint'] == 'us-west-2'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_create_service_role(self, mock_session):
        """Creates IAM service role."""
        mock_iam = MagicMock()
        mock_session.return_value.client.return_value = mock_iam
        client = SecurityAgentClient(region='us-east-1')
        arn = client.create_service_role('MyRole', '123456789012', 'bucket')
        assert arn == 'arn:aws:iam::123456789012:role/MyRole'
        mock_iam.create_role.assert_called_once()
        mock_iam.put_role_policy.assert_called_once()

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_create_code_review(self, mock_call):
        """Creates code review."""
        mock_call.return_value = {'codeReviewId': 'cr-1'}
        client = SecurityAgentClient(region='us-east-1')
        result = client.create_code_review('as-1', 'title', 'role', 's3://b/k.zip')
        assert result['codeReviewId'] == 'cr-1'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_start_code_review_job(self, mock_call):
        """Starts code review job."""
        mock_call.return_value = {'codeReviewJobId': 'cj-1'}
        client = SecurityAgentClient(region='us-east-1')
        result = client.start_code_review_job('as-1', 'cr-1')
        assert result['codeReviewJobId'] == 'cj-1'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_batch_get_code_review_jobs(self, mock_call):
        """Gets code review job status."""
        mock_call.return_value = {'codeReviewJobs': [{'status': 'COMPLETED'}]}
        client = SecurityAgentClient(region='us-east-1')
        result = client.batch_get_code_review_jobs('as-1', ['cj-1'])
        assert result['codeReviewJobs'][0]['status'] == 'COMPLETED'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_list_findings(self, mock_call):
        """Lists findings."""
        mock_call.return_value = {'findingsSummaries': [{'findingId': 'f-1'}]}
        client = SecurityAgentClient(region='us-east-1')
        result = client.list_findings('as-1', 'cj-1')
        assert len(result['findingsSummaries']) == 1

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._get_session')
    def test_upload_to_s3(self, mock_session):
        """Uploads file to S3."""
        mock_s3 = MagicMock()
        mock_session.return_value.client.return_value = mock_s3
        client = SecurityAgentClient(region='us-east-1')
        result = client.upload_to_s3('bucket', 'key.zip', '/tmp/f.zip')
        assert result == 's3://bucket/key.zip'

    @patch('awslabs.security_agent_mcp_server.aws_client.urllib.request.urlopen')
    def test_download_url(self, mock_urlopen):
        """Downloads content from URL."""
        mock_resp = MagicMock()
        mock_resp.read.return_value = b'diff content'
        mock_resp.__enter__ = lambda s: s
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp
        client = SecurityAgentClient(region='us-east-1')
        assert client.download_url('https://my-bucket.s3.amazonaws.com/diff.patch') == 'diff content'

    @patch('awslabs.security_agent_mcp_server.aws_client.SecurityAgentClient._call')
    def test_delete_agent_space(self, mock_call):
        """Deletes agent space."""
        mock_call.return_value = {}
        client = SecurityAgentClient(region='us-east-1')
        client.delete_agent_space('as-1')
        mock_call.assert_called_once_with('DeleteAgentSpace', {'agentSpaceId': 'as-1'})
