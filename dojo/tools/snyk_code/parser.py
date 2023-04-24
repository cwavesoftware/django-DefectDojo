import json

from cvss.cvss3 import CVSS3
from dojo.models import Finding
from dojo.tools.sarif.parser import *
import logging
import os
import zipfile

logger = logging.getLogger(__name__)

class SnykCodeParser(SarifParser):

    def get_scan_types(self):
        return ["Snyk Code Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Snyk code output file (snyk code test --json > snyk.json) can be imported in JSON format."

    def isZip(self, handle):
        if os.path.splitext(handle.temporary_file_path())[-1] != '.zip':
            return False
        with open(handle.temporary_file_path(), 'rb') as fin:
            content = fin.read()
            if len(content) < 4:
                return False
            sig = content[:4]
            if sig != b'PK\x03\x04':
                return False
        try:
            with zipfile.ZipFile(handle):
                logger.info('Valid .zip file uploaded')
        except:
            return False
        return True

    def get_tests(self, scan_type, handle):
        if self.isZip(handle):
            logger.info("Processing .zip file")
            json, html = self.process_zip(handle)
            tests = self._get_tests(json)

            descriptions = {}
            html = html.read().decode('utf8')
            finds = re.findall(r'<div id="([a-z0-9]{64})" (.+?)<!--finding-end-->', html, re.DOTALL)
            for f in finds:
                descriptions[f[0]] = f'<div id="{f[0]}" {f[1]}'

            for test in tests:
                for finding in test.findings:
                    for k,v in descriptions.items():
                        if finding.unique_id_from_tool == k:
                            finding.description = v
        else: # assuming is .json
            tests = self._get_tests(handle)
        return tests

    def process_zip(self, handle):
        z = zipfile.ZipFile(handle)
        json = None
        html = None
        for file in z.namelist():
            if os.path.splitext(file)[-1] == '.json':
                json = z.open(file)
            elif os.path.splitext(file)[-1] == '.html':
                html = z.open(file)
            if json != None and html != None:
                break
        else:
            logger.error('No .json and / or .html file found in zip archive')
            return (None, None)
        return json, html
    
    def _get_tests(self, handle):
        tree = json.load(handle)
        tests = list()
        for run in tree.get('runs', list()):
            test = ParserTest(
                name=run['tool']['driver']['name'],
                type='SAST',
                version=run['tool']['driver'].get('version'),
            )
            test.findings = self._get_findings(tree)
            tests.append(test)
        return tests
    
    def _get_findings(self, tree):
        items = list()
        for run in tree.get('runs', list()):
            items.extend(self.__get_items_from_run(run))
        return items
    
    def __get_items_from_run(self, run):
        items = list()
        rules = get_rules(run)
        artifacts = get_artifacts(run)
        run_date = self.__get_last_invocation_date(run)
        for result in run.get('results', list()):
            item = get_item(result, rules, artifacts, run_date)
            if item is not None:
                items.append(item)
        return items
    
    def __get_last_invocation_date(self, data):
        invocations = data.get('invocations', [])
        if len(invocations) == 0:
            return None
        # try to get the last 'endTimeUtc'
        raw_date = invocations[-1].get('endTimeUtc')
        if raw_date is None:
            return None
        # if the data is here we try to convert it to datetime
        return dateutil.parser.isoparse(raw_date)


def get_title(result, rule):
    title = None
    if title is None and rule is not None:
        if 'shortDescription' in rule:
            title = get_message_from_multiformatMessageString(rule['shortDescription'], rule)
        elif 'fullDescription' in rule:
            title = get_message_from_multiformatMessageString(rule['fullDescription'], rule)
        elif 'name' in rule:
            title = rule['name']
        elif 'id' in rule:
            title = rule['id']
    if title is None and 'message' in result:
        title = get_message_from_multiformatMessageString(result['message'], rule)

    if title is None:
        raise ValueError('No information found to create a title')

    return textwrap.shorten(title, 150)

def get_item(result, rules, artifacts, run_date):

    # see https://docs.oasis-open.org/sarif/sarif/v2.1.0/csprd01/sarif-v2.1.0-csprd01.html / 3.27.9
    kind = result.get('kind', 'fail')
    if kind != 'fail':
        return None

    # if finding is suppressed, mark it as False Positive
    # Note: see https://docs.oasis-open.org/sarif/sarif/v2.0/csprd02/sarif-v2.0-csprd02.html#_Toc10127852
    suppressed = False
    if result.get("suppressions"):
        suppressed = True

    # if there is a location get it
    file_path = None
    line = None
    if "locations" in result:
        location = result['locations'][0]
        if 'physicalLocation' in location:
            file_path = location['physicalLocation']['artifactLocation']['uri']
            # 'region' attribute is optionnal
            if 'region' in location['physicalLocation']:
                line = location['physicalLocation']['region']['startLine']

    # test rule link
    rule = rules.get(result.get('ruleId'))

    finding = Finding(
        title=get_title(result, rule),
        severity=get_severity(result, rule),
        description=get_description(result, rule),
        static_finding=True,  # by definition
        dynamic_finding=False,  # by definition
        false_p=suppressed,
        active=not suppressed,
        file_path=file_path,
        line=line,
        references=get_references(rule),
    )

    if 'ruleId' in result:
        finding.vuln_id_from_tool = result['ruleId']
        # for now we only support when the id of the rule is a CVE
        if cve_try(result['ruleId']):
            finding.unsaved_vulnerability_ids = [cve_try(result['ruleId'])]
    # some time the rule id is here but the tool doesn't define it
    if rule is not None:
        cwes_extracted = get_rule_cwes(rule)
        if len(cwes_extracted) > 0:
            finding.cwe = cwes_extracted[-1]

        # Some tools such as GitHub or Grype return the severity in properties instead
        if 'properties' in rule and 'security-severity' in rule['properties']:
            cvss = float(rule['properties']['security-severity'])
            severity = cvss_to_severity(cvss)
            finding.cvssv3_score = cvss
            finding.severity = severity

    # manage the case that some tools produce CWE as properties of the result
    cwes_properties_extracted = get_result_cwes_properties(result)
    if len(cwes_properties_extracted) > 0:
        finding.cwe = cwes_properties_extracted[-1]

    # manage fixes provided in the report
    if "fixes" in result:
        finding.mitigation = "\n".join([fix.get('description', {}).get("text") for fix in result["fixes"]])

    if run_date:
        finding.date = run_date

    # manage fingerprints
    # fingerprinting in SARIF is more complete than in current implementation
    # SARIF standard make it possible to have multiple version in the same report
    # for now we just take the first one and keep the format to be able to compare it
    if result.get("fingerprints"):
        hashes = get_fingerprints_hashes(result["fingerprints"])
        first_item = next(iter(hashes.items()))
        finding.unique_id_from_tool = first_item[1]['value']
    elif result.get("partialFingerprints"):
        # for this one we keep an order to have id that could be compared
        hashes = get_fingerprints_hashes(result["partialFingerprints"])
        sorted_hashes = sorted(hashes.keys())
        finding.unique_id_from_tool = "|".join([f'{key}:{hashes[key]["value"]}' for key in sorted_hashes])
    return finding