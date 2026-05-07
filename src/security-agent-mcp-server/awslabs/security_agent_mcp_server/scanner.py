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

"""Scanner — orchestrates zip, upload, create code review, start job, poll status, fetch findings."""

import gitignorefile
import os
import tempfile
import uuid
import zipfile
from awslabs.security_agent_mcp_server.aws_client import SecurityAgentClient
from awslabs.security_agent_mcp_server.state import StateManager
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional


MAX_ZIP_SIZE = 50 * 1024 * 1024  # 50MB

EXCLUDE_DIRS = {
    '.git',
    'node_modules',
    '__pycache__',
    '.venv',
    'venv',
    'dist',
    'build',
    'target',
    '.mypy_cache',
    '.pytest_cache',
    '.tox',
    '.next',
    'cdk.out',
}

EXCLUDE_FILES = {
    '.DS_Store',
    'Thumbs.db',
    '*.pyc',
    '*.pyo',
}


class Scanner:
    """Orchestrates code packaging, scan execution, and remediation."""

    def __init__(self, client: SecurityAgentClient, state: StateManager):
        """Initialize Scanner with API client and state manager."""
        self._client = client
        self._state = state

    async def start_scan(
        self, path: str = '.', title: Optional[str] = None, remediation: str = 'AUTOMATIC'
    ) -> dict:
        """Package code, upload to S3, and start a security scan."""
        config = self._state.get_config()
        agent_space_id = config['agent_space_id']
        service_role = config['service_role']
        s3_bucket = config['s3_bucket']

        scan_id = f'scan-{uuid.uuid4().hex[:8]}'
        title = title or f'pre-cr-{datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")}'

        # 1. Zip code
        zip_path = self._zip_code(path)
        zip_size = os.path.getsize(zip_path)
        if zip_size > MAX_ZIP_SIZE:
            os.unlink(zip_path)
            return {'error': f'Code too large ({zip_size // 1024 // 1024}MB). Max 50MB.'}

        # 2. Upload to S3
        try:
            s3_key = f'security-scans/{scan_id}/source.zip'
            s3_url = self._client.upload_to_s3(s3_bucket, s3_key, zip_path)
        finally:
            if os.path.exists(zip_path):
                os.unlink(zip_path)

        # 3. Create code review
        cr_result = self._client.create_code_review(
            agent_space_id=agent_space_id,
            title=title,
            service_role=service_role,
            s3_url=s3_url,
            code_remediation_strategy=remediation,
        )
        code_review_id = cr_result['codeReviewId']

        # 4. Start code review job
        job_result = self._client.start_code_review_job(
            agent_space_id=agent_space_id,
            code_review_id=code_review_id,
        )
        job_id = job_result['codeReviewJobId']

        # 5. Save state
        self._state.save_scan(
            scan_id,
            {
                'scan_id': scan_id,
                'code_review_id': code_review_id,
                'job_id': job_id,
                'agent_space_id': agent_space_id,
                'status': 'IN_PROGRESS',
                'title': title,
                'path': os.path.abspath(path),
                'started_at': datetime.now(timezone.utc).isoformat(),
                'zip_size_bytes': zip_size,
            },
        )

        return {
            'scan_id': scan_id,
            'code_review_id': code_review_id,
            'job_id': job_id,
            'status': 'STARTED',
            'title': title,
            'message': "Security scan started. Takes ~15-30 min. Ask 'scan status' anytime.",
        }

    async def get_status(self, scan_id: Optional[str] = None) -> dict:
        """Get the current status of a scan."""
        scan = self._state.get_scan(scan_id)
        if not scan:
            return {'error': 'No scan found. Start one with start_security_scan.'}

        result = self._client.batch_get_code_review_jobs(
            agent_space_id=scan['agent_space_id'],
            job_ids=[scan['job_id']],
        )
        jobs = result.get('codeReviewJobs', [])
        if not jobs:
            return {'error': f'Job {scan["job_id"]} not found.'}

        job = jobs[0]
        status = job.get('status', 'UNKNOWN')
        if scan.get('status') != status:
            scan['status'] = status
            self._state.save_scan(scan['scan_id'], scan)

        elapsed = ''
        if scan.get('started_at'):
            start = datetime.fromisoformat(scan['started_at'])
            elapsed = f'{int((datetime.now(timezone.utc) - start).total_seconds())}s'

        return {
            'scan_id': scan['scan_id'],
            'status': status,
            'title': scan.get('title'),
            'elapsed': elapsed,
            'steps': job.get('steps', []),
        }

    async def get_findings(self, scan_id: Optional[str] = None, severity: Optional[str] = None) -> dict:
        """Get findings from a completed scan."""
        scan = self._state.get_scan(scan_id)
        if not scan:
            return {'error': 'No scan found.'}

        # Check if complete first
        status_result = await self.get_status(scan_id=scan['scan_id'])
        if status_result.get('status') not in ('COMPLETED', 'PARTIALLY_COMPLETED'):
            return {
                'status': status_result.get('status'),
                'message': 'Scan not yet complete.',
                'elapsed': status_result.get('elapsed'),
            }

        result = self._client.list_findings(
            agent_space_id=scan['agent_space_id'],
            code_review_job_id=scan['job_id'],
        )
        findings = result.get('findingsSummaries', [])

        if severity:
            severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']
            severity_upper = severity.upper()
            if severity_upper in severity_order:
                min_idx = severity_order.index(severity_upper)
                allowed = set(severity_order[: min_idx + 1])
                findings = [f for f in findings if f.get('riskLevel', '').upper() in allowed]

        return {
            'scan_id': scan['scan_id'],
            'title': scan.get('title'),
            'total_findings': len(findings),
            'findings': findings,
        }

    async def stop_scan(self, scan_id: str) -> dict:
        """Stop a running scan."""
        scan = self._state.get_scan(scan_id)
        if not scan:
            return {'error': 'No scan found.'}

        self._client.stop_code_review_job(
            agent_space_id=scan['agent_space_id'],
            code_review_job_id=scan['job_id'],
        )
        scan['status'] = 'STOPPED'
        self._state.save_scan(scan['scan_id'], scan)
        return {'scan_id': scan['scan_id'], 'status': 'STOPPED'}

    async def start_remediation(self, scan_id: Optional[str] = None, finding_ids: Optional[list[str]] = None) -> dict:
        """Start code remediation for specific findings."""
        scan = self._state.get_scan(scan_id)
        if not scan:
            return {'error': 'No scan found.'}

        # If no finding_ids, get all from the scan
        if not finding_ids:
            result = self._client.list_findings(
                agent_space_id=scan['agent_space_id'],
                code_review_job_id=scan['job_id'],
            )
            findings = result.get('findingsSummaries', [])
            finding_ids = [f['findingId'] for f in findings]

        if not finding_ids:
            return {'error': 'No findings to remediate.'}

        self._client.start_code_remediation(
            agent_space_id=scan['agent_space_id'],
            job_id=scan['job_id'],
            finding_ids=finding_ids,
        )

        return {
            'status': 'REMEDIATION_STARTED',
            'finding_count': len(finding_ids),
            'finding_ids': finding_ids,
            'message': 'Code remediation started. Poll with get_remediation_diff to get fixes when ready.',
        }

    async def get_remediation_diff(self, scan_id: Optional[str] = None, finding_id: Optional[str] = None) -> dict:
        """Download remediation diffs for findings."""
        scan = self._state.get_scan(scan_id)
        if not scan:
            return {'error': 'No scan found.'}

        # Get finding with remediation details
        if not finding_id:
            # Get all findings and find one with completed remediation
            result = self._client.list_findings(
                agent_space_id=scan['agent_space_id'],
                code_review_job_id=scan['job_id'],
            )
            finding_ids = [f['findingId'] for f in result.get('findingsSummaries', [])]
        else:
            finding_ids = [finding_id]

        if not finding_ids:
            return {'error': 'No findings found.'}

        result = self._client.batch_get_findings(
            agent_space_id=scan['agent_space_id'],
            finding_ids=finding_ids,
        )

        diffs = []
        pending = []
        for finding in result.get('findings', []):
            remediation = finding.get('codeRemediationTask', {})
            status = remediation.get('status')

            if status == 'COMPLETED':
                for detail in remediation.get('taskDetails', []):
                    diff_link = detail.get('codeDiffLink')
                    if diff_link:
                        try:
                            diff_content = self._client.download_url(diff_link)
                            diffs.append(
                                {
                                    'finding_id': finding['findingId'],
                                    'finding_name': finding.get('name', ''),
                                    'diff': diff_content,
                                }
                            )
                        except Exception as e:
                            diffs.append(
                                {
                                    'finding_id': finding['findingId'],
                                    'finding_name': finding.get('name', ''),
                                    'error': f'Failed to download diff: {e}',
                                }
                            )
            elif status == 'IN_PROGRESS':
                pending.append(
                    {
                        'finding_id': finding['findingId'],
                        'name': finding.get('name', ''),
                        'status': 'IN_PROGRESS',
                    }
                )
            elif status == 'FAILED':
                pending.append(
                    {
                        'finding_id': finding['findingId'],
                        'name': finding.get('name', ''),
                        'status': 'FAILED',
                        'reason': remediation.get('statusReason', ''),
                    }
                )

        return {
            'scan_id': scan['scan_id'],
            'diffs_ready': len(diffs),
            'pending': len(pending),
            'diffs': diffs,
            'pending_details': pending,
        }

    def _zip_code(self, path: str) -> str:
        root = Path(path).resolve()
        gitignore_path = root / '.gitignore'
        matches = (
            gitignorefile.parse(str(gitignore_path))
            if gitignore_path.exists()
            else lambda _: False
        )

        tmp = tempfile.NamedTemporaryFile(suffix='.zip', delete=False)
        with zipfile.ZipFile(tmp.name, 'w', zipfile.ZIP_DEFLATED) as zf:
            for dirpath, dirnames, filenames in os.walk(root):
                # Skip always-excluded dirs
                dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
                for filename in filenames:
                    filepath = Path(dirpath) / filename
                    if filepath.is_symlink():
                        continue
                    rel_path = filepath.relative_to(root)
                    if not matches(str(filepath)) and not any(
                        filepath.match(p) for p in EXCLUDE_FILES
                    ) and filename not in EXCLUDE_FILES:
                        zf.write(filepath, rel_path)
        return tmp.name
