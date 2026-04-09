* **Process a single file:** `python3 ghsa_cve.py my-sbom.json`
* **Process and show ghsa -> cve mapping table:** `python3 ghsa_cve.py my-sbom.json -d`

Used Open Source Vulnerability (OSV) API instead of GitHub's so there's no need for auth tokens. Creates a new file with the same name as the input file but with "_cve" appended to the filename, and just swaps GHSA IDs for CVE IDs in the vulnerabilities   section. Run with Debug mode to see a mapping table for manual verification. Some GHSAs dont have a corresponding CVE, this just leaves them as is.

**example debug output:**
`python3 ghsa_cve.py grype-tomcat-sbom.json -d`
```
Reading: grype-tomcat-sbom.json...
  [+] Saved to: grype-tomcat-sbom_cve.json (10 IDs swapped)

  --- Debug Mapping Log ---
  GHSA-qppj-fm5r-hxr3       -> CVE-2023-44487
  GHSA-7w75-32cg-r6g2       -> CVE-2024-24549
  GHSA-wm9w-rjj3-j356       -> CVE-2024-34750
  GHSA-vvw4-rfwf-p6hx       -> CVE-2020-17527
  GHSA-f268-65qc-98vg       -> CVE-2020-13943
  GHSA-3p2h-wqq4-wf4h       -> CVE-2025-31650
  GHSA-7jqf-v358-p8g7       -> CVE-2024-38286
  GHSA-v682-8vv8-vpwr       -> CVE-2024-23672
  GHSA-25xr-qj8w-c4vf       -> CVE-2025-53506
  GHSA-4j3c-42xv-3f84       -> CVE-2025-52434
  -------------------------
```

**Changes in vulnerabilities section of output file: (truncated)**
**original:**
```json
"vulnerabilities": [
    {
      "bom-ref": "urn:uuid:8e2f2747-42ae-47e0-9aaa-c9fb4d89f870",
      "id": "GHSA-qppj-fm5r-hxr3",
      "source": {
        "name": "github-language-java",
        "url": "https://github.com/advisories/GHSA-qppj-fm5r-hxr3"
      },
      "references": [
        {
          "id": "GHSA-qppj-fm5r-hxr3",
          "source": {
            "name": "github-language-java",
            "url": "https://github.com/advisories/GHSA-qppj-fm5r-hxr3"
          }
        }
      ],
```
**CVE version:**
```json
"vulnerabilities": [
    {
      "bom-ref": "urn:uuid:8e2f2747-42ae-47e0-9aaa-c9fb4d89f870",
      "id": "CVE-2023-44487",
      "source": {
        "name": "github-language-java",
        "url": "https://github.com/advisories/GHSA-qppj-fm5r-hxr3"
      },
      "references": [
        {
          "id": "CVE-2023-44487",
          "source": {
            "name": "github-language-java",
            "url": "https://github.com/advisories/GHSA-qppj-fm5r-hxr3"
          }
        }
      ],
```