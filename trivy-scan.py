import subprocess, yaml
from git import Repo
from nob import Nob

cves = ('CVE-2021-4104', 'CVE-2021-44228', 'CVE-2021-45046', 'CVE-2022-22965')

# Get list of files changed in commit, and ignore any non-yaml files
repo = Repo('./')
changedFiles = [item.a_path for item in repo.index.diff('HEAD')]
print("Files changed: " + str(changedFiles))

yamlFiles = [f for f in changedFiles if f.endswith("yaml")]
print("YAML Files changed: " + str(yamlFiles))


# Actual Trivy Scan
def trivy_scan(files):
    for file in files:
        with open(file) as f:
            data = (yaml.load(f, Loader=yaml.SafeLoader))
            nob_tree = Nob(data)
            images = [(nob_tree["/spec/template/spec/containers/0/image"][:]),
                      (nob_tree["/spec/template/spec/initContainers/0/image"][:])]
            for image in images:
                print("Scanning image: " + image)
                subprocess.run(
                    [f'trivy --exit-code 0 --cache-dir .trivycache/ --no-progress --format template --template '
                     f'"@/tmp/trivy-gitlab.tpl" -o gl-container-scanning-report.json {image}'], shell=True)
                with open('gl-container-scanning-report.json') as f:
                    for line in f:
                        for cve in cves:
                            if cve.strip() in line:
                                print("Found log4j error: " + cve)
                                return -1
                print("No occurences of following CVEs found:" + str(cves))


trivy_scan(yamlFiles)
