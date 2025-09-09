import argparse
import os
import requests
import json
import dateutil
import datetime
import time
from urllib.parse import quote
import concurrent.futures
import subprocess
import traceback
import threading

'''
Description: Script to migrate Snyk ignores from project-scoped ignores v1 to API.
Author:  Tim Gowan (tim.gowan@snyk.io)
'''
# TODO: Set your API token as an environment variable
if not os.getenv('SNYK_API_TOKEN'):
    print("Could not find Snyk API key set as SNYK_API_TOKEN environment variable - exiting")
    exit(1)
snykToken = os.getenv('SNYK_API_TOKEN')

# TODO: Setting base variables
url = "https://api.snyk.io"  # Change value to match region. https://docs.snyk.io/working-with-snyk/regional-hosting-and-data-residency#available-snyk-regions
apiVersion = "2024-10-15"  # Set the API version.

# TODO Set to True to only retrieve issues that have been ignored
ignoredFlag = False


# TODO: Replace with your URLs
originUrls = {
    'github': 'https://github.com',
    'github-enterprise': 'https://github.com',
    'gitlab': 'https://gitlab.com',
    'bitbucket-server': 'https://bitbucket.org',
    'bitbucket-cloud': 'https://bitbucket.org',
    'azure-devops': 'https://dev.azure.com',
    'azure-repos': 'https://dev.azure.com',
    'bitbucket-connect-app': 'https://bitbucket.org'
}

class Group:
    def __init__(self, groupId, orgId=None):
        # string
        self.id = groupId
        if orgId:
            self.orgs = [Organization(orgId)]
        else:
            self.orgs = self.listOrgsInGroup()

    def listOrgsInGroup(self, orgName=None, orgSlug=None):
        '''
        # GET /rest/groups/{group_id}/orgs?version={apiVersion}
        '''
        uri = f"/rest/groups/{self.id}/orgs?version={apiVersion}"
        if orgName:
            uri += f"&name={orgName}"
        if orgSlug:
            uri += f"&slug={orgSlug}"
        if limit:
            uri += f"&limit={limit}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
            organizations = []
            while response.status_code in [200, 429]:
                if response.status_code == 429:
                    print(f"Rate limit exceeded, retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                response_json = response.json()
                if "data" in response_json:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = [executor.submit(Organization, org['id']) for org in response_json['data']]
                        for future in concurrent.futures.as_completed(futures):
                            organizations.append(future.result())
                uri = response_json["links"].get("next") if "links" in response_json else None
                if uri:
                    response = requests.get(url + uri, headers=headers)
                else:
                    break

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        return organizations

class Organization:
    def __init__(self, orgId, projectId=None):
        self.id = orgId
        # Getting org details because listOrgsInGroup does not provide enough detail
        org = self.getOrg()
        try:
            self.integrations = self.listIntegrations()
            self.groupId = org['data']['attributes']['group_id']
            self.name = org['data']['attributes']['name']
            self.slug = org['data']['attributes']['slug']
            if projectId:
                self.projects = [Project(self, projectId)]
            else:
                self.projects = self.listProjectsInOrg()
                print(f"    {len(self.projects)} projects found in {self.name}")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)

    def printOrg(self):
        print(f"Organization ID: {self.id}")
        print(f"    Group ID: {self.groupId}")
        print(f"    Name: {self.name}")
        print(f"    Slug: {self.slug}")

    def getOrg(self):
        '''
        # GET /rest/orgs/{orgId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.id}?version={apiVersion}"
        if limit:
            uri += f"&limit={limit}"

        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        # Uncomment print statement to debug
        # print(json.dumps(response.json(), indent=4))
        return response.json()

    def listProjectsInOrg(self, projectName=None, scanType=None):
        '''
        # GET /rest/orgs/{orgId}/projects?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.id}/projects?version={apiVersion}"
        if limit:
            uri += f"&limit={limit}"
        if projectName:
            uri += f"&name={projectName}"
        if scanType:
            uri += f"&types={quote(scanType)}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
            projects = []
            while response.status_code in [200, 429]:
                if response.status_code == 429:
                    print(f"Rate limit exceeded, retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                response_json = response.json()
                print(json.dumps(response.json(), indent=4))
                if "data" in response_json:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                        futures = [executor.submit(Project, self, org['id']) for org in response_json['data']]
                        for future in concurrent.futures.as_completed(futures):
                            projects.append(future.result())
                uri = response_json["links"].get("next") if "links" in response_json else None
                if uri:
                    response = requests.get(url + uri, headers=headers)
                else:
                    break
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        # Uncomment print statement to debug
        print(json.dumps(response.json(), indent=4))
        return projects

    def listIntegrations(self):
        '''
        # GET https://api.snyk.io/v1/org/{orgId}/integrations
        '''
        uri = f"/v1/org/{self.id}/integrations"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'token {snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
            # print(json.dumps(response.json(), indent=4))
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        return response.json()

class Project:
    def __init__(self, organization, projectId):
        self.organization = organization
        self.id = projectId
        # Getting project details because listProjectsInOrg does not provide enough metadata
        project = self.getProject()
        try:
            self.name = project['data']['attributes']['name']
            self.type = project['data']['attributes']['type']
            self.targetReference = project['data']['attributes']['target_reference']
            self.origin = project['data']['attributes']['origin']
            self.integrationId = self.getIntegrationId()
            self.targetId = project['data']['relationships']['target']['data']['id']
            self.status = project['data']['attributes']['status']
            self.repoUrl = originUrls[self.origin] + '/' + self.name.split('(')[0]
            self.issues = self.getProjectIssues(status='open', include_ignored=ignoredFlag)

            # self.ignores = self.getIgnoresV1() # Opting for the issue-based approach for delete consistency
            # if len of issues > 0, then we have issues
            if self.issues:
                print(f"    {len(self.issues)} issues found in {self.repoUrl}")
                self.sarif = None
                self.sarif_lock = threading.Lock()

                self.sarif = self.testApi()
                # Guarantee presence of SARIF before continuing.
                with self.sarif_lock:
                    while self.sarif is None:
                        time.sleep(delay)
                    # Decorate issues with SARIF data
                    for issue in self.issues:
                        issue.assetFindingV1 = issue.getAssetFindingV1()
                        #print(f"Decorated issue {issue.id} with SARIF data")
            else:
                print(f"    No issues found in {self.repoUrl}")

        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)

    def getIntegrationId(self):
        '''
        Helper function to get the integration ID from the project name and enumerated dictionary.
        '''
        if self.origin not in originUrls:
            print(f"ERROR: {self.origin} not an SCM integration - exiting.")
            exit(1)
        for key in self.organization.integrations:
            if key == self.origin:
                return self.organization.integrations[key]
        return None

    def printProject(self):
        print(f"    Project ID: {self.id}")
        print(f"        Project Name: {self.name}")
        print(f"        Project Type: {self.type}")
        print(f"        Target Reference: {self.targetReference}")
        print(f"        Origin: {self.origin}")
        print(f"        Target ID: {self.targetId}")
        print(f"        Status: {self.status}")
        print(f"        Repo URL: {self.repoUrl}")
        print(f"        Integration ID: {self.integrationId}")
        print(f"        Issues Count: {len(self.issues)}")

    def getProject(self):
        '''
        # GET /rest/orgs/{orgId}/projects/{projectId}?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/projects/{self.id}?version={apiVersion}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Request URL: {url + uri}")
            traceback.print_exc()
            exit(1)
        # Uncomment print statement to debug
        # print(json.dumps(response.json(), indent=4))
        return response.json()

    def getProjectIssues(self, scanType=None, status=None, include_ignored=None, created_after=None,
                         created_before=None):
        '''
        # GET /rest/orgs/{orgId}/issues?version={apiVersion}
        '''
        uri = f"/rest/orgs/{self.organization.id}/issues?version={apiVersion}"
        if self.id is not None:
            uri += f"&scan_item.id={self.id}&scan_item.type=project"
        if limit:
            uri += f"&limit={limit}"
        if status is not None:
            uri += f"&status={status}"
        if scanType is not None:
            uri += f"&type={scanType}"
        if created_after is not None:
            created_after = dateutil.parser.parse(created_after).astimezone()
            created_after_url_safe = quote(created_after.isoformat())
            uri += f"&created_after={created_after_url_safe}"
        if created_before is not None:
            created_before = dateutil.parser.parse(created_before).astimezone()
            created_before_url_safe = quote(created_before.isoformat())
            uri += f"&created_before={created_before_url_safe}"
        if include_ignored:
            uri += "&ignored=True"

        headers = {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            issues = []
            while response.status_code in [200, 429]:
                if response.status_code == 429:
                    print(f"Rate limit exceeded, retrying in {delay} seconds...")
                    time.sleep(delay)
                    continue
                response_json = response.json()
                if "data" in response_json:
                    for issue in response_json['data']:
                        # Uncomment print statement to debug
                        issues.append(Issue(project=self,
                                            organization=self.organization,
                                            id=issue['id'],
                                            effectiveSeverityLevel=issue['attributes']['effective_severity_level'],
                                            title=issue['attributes']['title'],
                                            key=issue['attributes']['key'],
                                            ignored=issue['attributes']['ignored'],
                                            createdAt=issue['attributes']['created_at'],
                                            updatedAt=issue['attributes']['problems'][0]['updated_at'],
                                            ))
                uri = response_json["links"].get("next") if "links" in response_json else None
                if uri:
                    response = requests.get(url + uri, headers=headers)
                else:
                    break
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()
            exit(1)
        return issues

    def testApi(self, continuous_monitor=False):
        '''
        Experimental API
        POST /orgs/{org_id}/tests?version={apiVersion}
        '''
        localDelay = 5
        apiVersion = "2024-10-14~experimental"
        uri = f"/rest/orgs/{self.organization.id}/tests?version={apiVersion}"
        payload = {
            "data": {
                "type": "test",
                "attributes": {
                    "continuous_monitor": continuous_monitor,
                    "options": {
                        "integration_id": self.integrationId,
                        "repo_url": self.repoUrl,
                        "revision": self.targetReference
                    }
                }
            }
        }
        headers = {
            'Content-Type': 'application/vnd.api+json',
            'Authorization': f'{snykToken}'
        }
        inProgressDisplayedFlag = False
        try:
            while True:
                try:
                    response = requests.post(
                        url + uri,
                        headers=headers,
                        json=payload
                    )
                    break
                except requests.exceptions.HTTPError as err:
                    if response.status_code == 429:  # Too Many Requests
                        print(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                        time.sleep(localDelay)
                        localDelay = min(localDelay * 2, max_delay)  # Exponential backoff with a maximum delay
                    else:
                        print(f"An unexpected error occurred: {err}{response.text}")
                        raise err
            if response.status_code == 201:
                while True:
                    try:
                        uri = response.json()['links']['self']['href']
                        response = requests.get(
                            url + uri,
                            headers=headers
                        )
                        response.raise_for_status()
                        while response.status_code in [200, 429] and response.json()['data']['attributes'][
                            'state'] == 'in_progress':
                            if response.status_code == 429:
                                print(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                                time.sleep(localDelay)
                                continue
                            response = requests.get(
                                url + uri,
                                headers=headers
                            )
                            response.raise_for_status()
                            state = response.json()['data']['attributes']['state']
                            # Only want to show this once.
                            if inProgressDisplayedFlag == False:
                                print(f"    SARIF generation {state}: {self.repoUrl}")
                                # Uncomment to make stdout less noisy with polling
                                inProgressDisplayedFlag = True
                            if state == 'completed':
                                print(f"    SARIF generation {state}: {self.repoUrl}")
                                # Different API, don't need to share rate limit
                                # print(response.json()['data']['attributes']['findings'][0]['findings_url'])
                                response = requests.get(
                                    response.json()['data']['attributes']['findings'][0]['findings_url']
                                )
                                response.raise_for_status()
                                if response.content:
                                    return response.json()  # Finally got the SARIF
                        break
                    except requests.exceptions.HTTPError as err:
                        if response.status_code == 429:  # Too Many Requests
                            print(f"Rate limit exceeded, retrying in {localDelay} seconds...")
                            time.sleep(localDelay)
                            localDelay = min(localDelay * 2, max_delay)  # Exponential backoff with a maximum delay
                        else:
                            raise err

        except requests.exceptions.RequestException as e:
            print(f"Request URL: {url + uri}")
            print(f"Request Payload: {json.dumps(payload, indent=4)}")
            print(f"Error downloading file: {e}")
            traceback.print_exc()
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            traceback.print_exc()


class Issue:
    def __init__(self, organization: Organization, project: Project, id, effectiveSeverityLevel, title, key, ignored,
                 createdAt, updatedAt):
        self.organization = organization
        self.project = project
        self.id = id
        self.effectiveSeverityLevel = effectiveSeverityLevel
        self.title = title
        self.key = key
        self.createdAt = createdAt
        self.updatedAt = updatedAt
        self.ignored = ignored
        # Get the issue details for SAST projects
        if self.project.type == 'sast':
            issueDetails = self.getCodeIssueDetails()
            self.cwe = issueDetails['attributes']['cwe']
            self.endLine = issueDetails['attributes']['primaryRegion']['endLine']
            self.endColumn = issueDetails['attributes']['primaryRegion']['endColumn']
            self.startLine = issueDetails['attributes']['primaryRegion']['startLine']
            self.startColumn = issueDetails['attributes']['primaryRegion']['startColumn']
            self.score = issueDetails['attributes']['priorityScore']
            self.primaryFilePath = issueDetails['attributes']['primaryFilePath']
            self.fingerprint = issueDetails['attributes']['fingerprint']
            # self.assetFindingV1 = self.project.getAssetFindingV1(self.id, self.fingerprint)
            # self.assetFindingV1 = self.getAssetFindingV1()

    def printIssue(self):
        print(f"        Issue ID: {self.id}")
        print(f"            Key: {self.key}")
        #print(f"            Priority Score: {self.score}")
        print(f"            snyk/asset/finding/v1: {self.assetFindingV1}")
        # print(f"            Fingerprint: {self.fingerprint}")
        print(f"            Effective Severity Level: {self.effectiveSeverityLevel}")
        print(f"            CWE: {self.cwe}")
        print(f"            Title: {self.title}")
        print(f"            Ignored: {self.ignored}")
        print(f"            Created At: {self.createdAt}")
        print(f"            Updated At: {self.updatedAt}")
        # print(f"            Primary File Path: {self.primaryFilePath}")
        # print(f"            End Line: {self.endLine}")
        # print(f"            End Column: {self.endColumn}")
        # print(f"            Start Line: {self.startLine}")
        # print(f"            Start Column: {self.startColumn}")

    def getCodeIssueDetails(self):
        '''
        Experimental API
        GET /orgs/{org_id}/code_issue_details/{issue_id}?version={apiVersion}&project_id={project_id}
        :return:
        '''
        apiVersion = "2024-10-14~experimental"
        uri = f"/rest/orgs/{self.organization.id}/code_issue_details/{self.key}?version={apiVersion}&project_id={self.project.id}"
        headers = {
            'Content-Type': 'application/json',
            'Authorization': f'{snykToken}'
        }
        try:
            response = requests.get(
                url + uri,
                headers=headers
            )
            response.raise_for_status()
            #print("JSON RESPONSE FOR CODE ISSUE DETAILS:")
            #print(json.dumps(response.json(), indent=4))
        except requests.exceptions.RequestException as e:
            print(f"An unexpected error occurred: {e}")
            print(f"Request URL: {url + uri}")
            traceback.print_exc()
            exit(1)
        return response.json()['data']

    def getAssetFindingV1(self):
        """
        Retrieves the Snyk fingerprint for an issue in a specified file and line.
        Returns:
          The snyk/asset/finding/v1 as a string, or None if not found.
        """
        try:
            # Search for matching result using JQ-like logic
            for run in self.project.sarif['runs']:
                for result in run['results']:
                    if self.fingerprint == result['fingerprints']['1']:
                        return result['fingerprints']['snyk/asset/finding/v1']
            print(f"Asset Finding V1 not found for IssueId: {self.id}")
            return None
        except Exception as e:
            print(f"An unexpected error occurred: {e}")
            self.printIssue()
            traceback.print_exc()
            exit(1)


if __name__ == '__main__':
    # Parsing Command Line Arguments
    parser = argparse.ArgumentParser(
        description='Migrate Snyk ignores from project-scoped ignores v1 to  API.'
                    ' --orgName or --orgId required.')
    # Required fields:
    parser.add_argument('--groupId', '-g',
                        type=str,
                        help='Snyk Group ID, groupId of the group to query.',
                        required=False)
    parser.add_argument('--orgId', '-o',
                        type=str,
                        help='Snyk Organization ID',
                        required=False)
    parser.add_argument('--projectId', '-p',
                        type=str,
                        help='Snyk project ID - If used, orgId must also be provided',
                        required=False)

    args = parser.parse_args()
    # Set global variables
    limit = 100  # Limit for pagination
    max_workers = 5  # Number of threads for concurrent requests
    delay = 5  # Delay for rate limiting
    max_delay = 120  # Maximum delay in seconds
    startTime = time.time()


    if args.orgId and not args.projectId and not args.groupId:
        orgs = [Organization(args.orgId)]
    elif args.orgId and args.projectId:
        orgs = [Organization(args.orgId, args.projectId)]
    elif args.groupId:
        group = Group(args.groupId, args.orgId)
        orgs = group.orgs

    for org in orgs:
        print(f"--------------------------------------------")
        print(f"Processing Issue Clusters for {org.name} ({org.id})")
        print(f"--------------------------------------------")
        org.printOrg()

    for project in org.projects:
        project.printProject()
        if project.issues:
            for issue in project.issues:
                issue.printIssue()

    endTime = time.time()
    print(f"Total time taken: {endTime - startTime} seconds")
    print("Done.")
    exit(0)
