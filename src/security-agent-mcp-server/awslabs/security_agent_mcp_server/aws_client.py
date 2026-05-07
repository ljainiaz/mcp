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

"""AWS SecurityAgent API client using direct SigV4-signed HTTP calls."""

import boto3
import json
import urllib.error
import urllib.request
from botocore.auth import SigV4Auth
from botocore.awsrequest import AWSRequest
from typing import Any, Optional


ENDPOINT_TEMPLATE = 'https://securityagent.{region}.api.aws'


class SecurityAgentClient:
    """Client for AWS SecurityAgent APIs using SigV4-signed HTTP calls."""

    def __init__(self, region: str = 'us-east-1'):
        """Initialize SecurityAgent client."""
        self.region = region
        self.endpoint = ENDPOINT_TEMPLATE.format(region=region)

    def _get_session(self):
        """Fresh session each call to pick up rotated credentials."""
        return boto3.Session(region_name=self.region)

    def _call(self, operation: str, body: dict) -> dict:
        url = f'{self.endpoint}/{operation}'
        data = json.dumps(body).encode()
        session = self._get_session()
        credentials = session.get_credentials().get_frozen_credentials()
        request = AWSRequest(
            method='POST', url=url, data=data, headers={'Content-Type': 'application/json'}
        )
        SigV4Auth(credentials, 'securityagent', self.region).add_auth(request)

        req = urllib.request.Request(
            url=url,
            data=data,
            headers=dict(request.headers),
            method='POST',
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                return json.loads(resp.read())
        except urllib.error.HTTPError as e:
            error_body = e.read().decode() if e.fp else ''
            raise RuntimeError(f'{operation} failed ({e.code}): {error_body}') from e

    def get_caller_identity(self) -> dict:
        """Get the current AWS caller identity."""
        return self._get_session().client('sts').get_caller_identity()

    def list_agent_spaces(self) -> list[dict]:
        """List all SecurityAgent agent spaces."""
        result = self._call('ListAgentSpaces', {})
        return result.get('agentSpaceSummaries', [])

    def get_agent_space(self, agent_space_id: str) -> dict:
        """Get details for a specific agent space."""
        result = self._call('BatchGetAgentSpaces', {'agentSpaceIds': [agent_space_id]})
        spaces = result.get('agentSpaces', [])
        return spaces[0] if spaces else {}

    def update_agent_space(
        self,
        agent_space_id: str,
        name: str,
        iam_roles: Optional[list[str]] = None,
        s3_buckets: Optional[list[str]] = None,
    ) -> dict:
        """Update an agent space with roles and buckets."""
        body: dict[str, Any] = {'agentSpaceId': agent_space_id, 'name': name}
        aws_resources = {}
        if iam_roles:
            aws_resources['iamRoles'] = iam_roles
        if s3_buckets:
            aws_resources['s3Buckets'] = s3_buckets
        if aws_resources:
            body['awsResources'] = aws_resources
        return self._call('UpdateAgentSpace', body)

    def simulate_role_s3_permissions(self, role_arn: str, bucket_name: str) -> bool:
        """Check if a role has S3 read permissions on a bucket using SimulatePrincipalPolicy."""
        iam = self._get_session().client('iam')
        try:
            result = iam.simulate_principal_policy(
                PolicySourceArn=role_arn,
                ActionNames=['s3:GetObject', 's3:ListBucket'],
                ResourceArns=[
                    f'arn:aws:s3:::{bucket_name}',
                    f'arn:aws:s3:::{bucket_name}/*',
                ],
            )
            for eval_result in result.get('EvaluationResults', []):
                if eval_result.get('EvalDecision') != 'allowed':
                    return False
            return True
        except Exception:
            return False

    def create_agent_space(
        self, name: str, service_role: Optional[str] = None, s3_bucket: Optional[str] = None
    ) -> dict:
        """Create a new SecurityAgent agent space."""
        body: dict[str, Any] = {'name': name}
        if service_role or s3_bucket:
            body['awsResources'] = {}
            if service_role:
                body['awsResources']['iamRoles'] = [service_role]
            if s3_bucket:
                body['awsResources']['s3Buckets'] = [s3_bucket]
        return self._call('CreateAgentSpace', body)

    def create_s3_bucket(self, bucket_name: str) -> str:
        """Create S3 bucket for code uploads."""
        s3 = self._get_session().client('s3')
        create_args: dict[str, Any] = {'Bucket': bucket_name}
        if self.region != 'us-east-1':
            create_args['CreateBucketConfiguration'] = {'LocationConstraint': self.region}
        s3.create_bucket(**create_args)
        s3.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True,
            },
        )
        return bucket_name

    def create_service_role(self, role_name: str, account_id: str, bucket_name: str) -> str:
        """Create IAM service role for Security Agent with S3 + CloudWatch Logs access."""
        iam = self._get_session().client('iam')

        trust_policy = json.dumps(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Principal': {'Service': 'securityagent.amazonaws.com'},
                        'Action': 'sts:AssumeRole',
                    }
                ],
            }
        )

        permissions_policy = json.dumps(
            {
                'Version': '2012-10-17',
                'Statement': [
                    {
                        'Effect': 'Allow',
                        'Action': ['s3:GetObject', 's3:GetObjectVersion', 's3:ListBucket'],
                        'Resource': [
                            f'arn:aws:s3:::security-agent-scans-{account_id}-*',
                            f'arn:aws:s3:::security-agent-scans-{account_id}-*/*',
                        ],
                    },
                    {
                        'Effect': 'Allow',
                        'Action': [
                            'logs:CreateLogGroup',
                            'logs:CreateLogStream',
                            'logs:PutLogEvents',
                        ],
                        'Resource': f'arn:aws:logs:*:{account_id}:log-group:/aws/securityagent/*',
                    },
                    {
                        'Effect': 'Allow',
                        'Action': ['iam:SimulatePrincipalPolicy', 'iam:GetRole'],
                        'Resource': f'arn:aws:iam::{account_id}:role/{role_name}',
                    },
                ],
            }
        )

        iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName='SecurityAgentCodeReviewAccess',
            PolicyDocument=permissions_policy,
        )

        return f'arn:aws:iam::{account_id}:role/{role_name}'

    def create_code_review(
        self,
        agent_space_id: str,
        title: str,
        service_role: str,
        s3_url: str,
        code_remediation_strategy: str = 'DISABLED',
    ) -> dict:
        """Create a code review resource."""
        return self._call(
            'CreateCodeReview',
            {
                'agentSpaceId': agent_space_id,
                'title': title,
                'serviceRole': service_role,
                'assets': {'sourceCode': [{'s3Location': s3_url}]},
                'codeRemediationStrategy': code_remediation_strategy,
            },
        )

    def start_code_review_job(self, agent_space_id: str, code_review_id: str) -> dict:
        """Start a code review scan job."""
        return self._call(
            'StartCodeReviewJob',
            {
                'agentSpaceId': agent_space_id,
                'codeReviewId': code_review_id,
            },
        )

    def batch_get_code_review_jobs(self, agent_space_id: str, job_ids: list[str]) -> dict:
        """Get status of code review jobs."""
        return self._call(
            'BatchGetCodeReviewJobs',
            {
                'agentSpaceId': agent_space_id,
                'codeReviewJobIds': job_ids,
            },
        )

    def stop_code_review_job(self, agent_space_id: str, code_review_job_id: str) -> dict:
        """Stop a running code review job."""
        return self._call(
            'StopCodeReviewJob',
            {
                'agentSpaceId': agent_space_id,
                'codeReviewJobId': code_review_job_id,
            },
        )

    def list_findings(self, agent_space_id: str, code_review_job_id: str) -> dict:
        """List all findings for a completed scan job, handling pagination."""
        all_findings = []
        body = {'agentSpaceId': agent_space_id, 'codeReviewJobId': code_review_job_id}
        while True:
            result = self._call('ListFindings', body)
            all_findings.extend(result.get('findingsSummaries', []))
            next_token = result.get('nextToken')
            if not next_token:
                break
            body['nextToken'] = next_token
        return {'findingsSummaries': all_findings}

    def batch_get_findings(self, agent_space_id: str, finding_ids: list[str]) -> dict:
        """Get detailed findings by ID."""
        return self._call(
            'BatchGetFindings',
            {
                'agentSpaceId': agent_space_id,
                'findingIds': finding_ids,
            },
        )

    def start_code_remediation(
        self, agent_space_id: str, job_id: str, finding_ids: list[str]
    ) -> dict:
        """Start code remediation for findings."""
        return self._call(
            'StartCodeRemediation',
            {
                'agentSpaceId': agent_space_id,
                'pentestJobId': job_id,
                'findingIds': finding_ids,
            },
        )

    def download_url(self, url: str) -> str:
        """Download content from a presigned S3 URL."""
        from urllib.parse import urlparse

        parsed = urlparse(url)
        if not parsed.hostname or not (parsed.hostname.endswith('.amazonaws.com') or parsed.hostname.endswith('.aws')):
            raise ValueError(f'Refusing to download from non-AWS domain: {parsed.hostname}')
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode('utf-8')

    def upload_to_s3(self, bucket: str, key: str, file_path: str) -> str:
        """Upload a file to S3."""
        self._get_session().client('s3').upload_file(file_path, bucket, key)
        return f's3://{bucket}/{key}'

    def delete_agent_space(self, agent_space_id: str) -> dict:
        """Delete an agent space."""
        return self._call('DeleteAgentSpace', {'agentSpaceId': agent_space_id})

    def delete_s3_bucket(self, bucket_name: str) -> None:
        """Empty and delete S3 bucket."""
        s3 = self._get_session().client('s3')
        paginator = s3.get_paginator('list_objects_v2')
        for page in paginator.paginate(Bucket=bucket_name):
            objects = page.get('Contents', [])
            if objects:
                s3.delete_objects(
                    Bucket=bucket_name,
                    Delete={'Objects': [{'Key': obj['Key']} for obj in objects]},
                )
        s3.delete_bucket(Bucket=bucket_name)

    def delete_service_role(self, role_name: str) -> None:
        """Delete inline policies then delete the IAM role."""
        iam = self._get_session().client('iam')
        policies = iam.list_role_policies(RoleName=role_name).get('PolicyNames', [])
        for policy_name in policies:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)
