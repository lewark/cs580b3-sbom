import json
import urllib.request
import urllib.error
import argparse
from pathlib import Path
from typing import Optional

api_cache = {}

def fetch_cve_from_osv(ghsa_id: str) -> Optional[str]:
    # OSV API to find the CVE equivalent for a GHSA ID. (no need for gh token)
    
    if ghsa_id in api_cache:
        return api_cache[ghsa_id]

    url = f"https://api.osv.dev/v1/vulns/{ghsa_id}"
    
    try:
        req = urllib.request.Request(url)
        with urllib.request.urlopen(req) as response:
            data = json.loads(response.read().decode('utf-8'))
            
            # check response aliases list
            aliases = data.get("aliases", [])
            for alias in aliases:
                if alias.startswith("CVE-"):
                    api_cache[ghsa_id] = alias
                    return alias
                    
    except (urllib.error.HTTPError, urllib.error.URLError):
        pass 

    api_cache[ghsa_id] = None
    return None


def process_sbom(input_path: Path, output_path: Path, debug: bool = False):
    print(f"Reading: {input_path.name}...")
    
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            sbom = json.load(f)
    except UnicodeDecodeError:  
        try:
            with open(input_path, 'r', encoding='utf-16') as f:
                sbom = json.load(f)
        except UnicodeDecodeError:
            print(f"  [!] Failed to read {input_path.name} (tried UTF-8 and UTF-16)")
            return
    except Exception as e:
        print(f"  [!] Failed to read {input_path.name}: {e}")
        return

    vulnerabilities = sbom.get("vulnerabilities", [])
    if not vulnerabilities:
        print("  [!] No vulnerabilities found.")
        return

    swapped_count = 0
    debug_log = []

    for vuln in vulnerabilities:
        vuln_id = vuln.get("id", "")

        if vuln_id.startswith("GHSA-"):
            cve_id = fetch_cve_from_osv(vuln_id)
            if cve_id:
                vuln["id"] = cve_id
                swapped_count += 1  # type: ignore
                debug_log.append((vuln_id, cve_id))

                for ref in vuln.get("references", []):
                    if ref.get("id") == vuln_id:
                        ref["id"] = cve_id
            else:
                debug_log.append((vuln_id, "NO CVE FOUND"))

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2)
        
    print(f"  [+] Saved to: {output_path.name} ({swapped_count} IDs swapped)")

    if debug and debug_log:
        print("\n  --- Debug Mapping Log ---")
        for old_id, new_id in debug_log:
            print(f"  {old_id:<25} -> {new_id}")
        print("  -------------------------\n")


def main():
    parser = argparse.ArgumentParser(description="Convert GHSA IDs to CVEs in CycloneDX SBOMs.")
    parser.add_argument(
        "target", 
        help="Path to a single SBOM .json file."
    )
    parser.add_argument(
        "-d", "--debug", 
        action="store_true", 
        help="Print a detailed mapping of what was swapped."
    )
    
    args = parser.parse_args()
    target_path = Path(args.target)

    if target_path.is_file() and target_path.suffix == '.json':
        # output file name is input file name + _cve.json
        output_path = target_path.with_name(f"{target_path.stem}_cve{target_path.suffix}")
        process_sbom(target_path, output_path, args.debug)
        
    else:
        print("Error: Target must be a valid sbom.json file.")

if __name__ == "__main__":
    main()