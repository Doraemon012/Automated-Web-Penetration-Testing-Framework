import json

class Reporter:
    def __init__(self):
        self.findings = []

    def add_findings(self, issues):
        self.findings.extend(issues)

    def save_json(self, filename="report.json"):
        with open(filename, "w") as f:
            json.dump(self.findings, f, indent=4)
        print(f"[+] JSON report saved: {filename}")

    def save_markdown(self, filename="report.md"):
        with open(filename, "w") as f:
            f.write("# 🛡 Vulnerability Report\n\n")
            for issue in self.findings:
                f.write(f"## {issue['vulnerability']}\n")
                f.write(f"- **URL:** {issue['url']}\n")
                if issue["payload"]:
                    f.write(f"- **Payload:** `{issue['payload']}`\n")
                f.write(f"- **Severity:** {issue['severity']}\n")
                f.write(f"- **Description:** {issue['description']}\n\n")
        print(f"[+] Markdown report saved: {filename}")
