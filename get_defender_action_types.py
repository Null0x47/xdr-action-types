import argparse
import json
import sys
import time
import urllib.parse

import requests

ALL_TABLES = [
    "AADSignInEventsBeta",
    "AADSpnSignInEventsBeta",
    "AlertEvidence",
    "AlertInfo",
    "BehaviorEntities",
    "BehaviorInfo",
    "CampaignInfo",
    "CloudAppEvents",
    "CloudAuditEvents",
    "CloudProcessEvents",
    "CloudStorageAggregatedEvents",
    "DataSecurityBehaviors",
    "DataSecurityEvents",
    "DeviceBaselineComplianceAssessment",
    "DeviceBaselineComplianceAssessmentKB",
    "DeviceBaselineComplianceProfiles",
    "DeviceEvents",
    "DeviceFileCertificateInfo",
    "DeviceFileEvents",
    "DeviceImageLoadEvents",
    "DeviceInfo",
    "DeviceLogonEvents",
    "DeviceNetworkEvents",
    "DeviceNetworkInfo",
    "DeviceProcessEvents",
    "DeviceRegistryEvents",
    "DeviceTvmBrowserExtensions",
    "DeviceTvmBrowserExtensionsKB",
    "DeviceTvmCertificateInfo",
    "DeviceTvmHardwareFirmware",
    "DeviceTvmInfoGathering",
    "DeviceTvmInfoGatheringKB",
    "DeviceTvmSecureConfigurationAssessment",
    "DeviceTvmSecureConfigurationAssessmentKB",
    "DeviceTvmSoftwareEvidenceBeta",
    "DeviceTvmSoftwareInventory",
    "DeviceTvmSoftwareVulnerabilities",
    "DeviceTvmSoftwareVulnerabilitiesKB",
    "DisruptionAndResponseEvents",
    "EmailAttachmentInfo",
    "EmailEvents",
    "EmailPostDeliveryEvents",
    "EmailUrlInfo",
    "EntraIdSignInEvents",
    "EntraIdSpnSignInEvents",
    "ExposureGraphEdges",
    "ExposureGraphNodes",
    "FileMaliciousContentInfo",
    "GraphApiAuditEvents",
    "IdentityAccountInfo",
    "IdentityDirectoryEvents",
    "IdentityEvents",
    "IdentityInfo",
    "IdentityLogonEvents",
    "IdentityQueryEvents",
    "MessageEvents",
    "MessagePostDeliveryEvents",
    "MessageUrlInfo",
    "OAuthAppInfo",
    "UrlClickEvents",
]

BASE_URL = "https://security.microsoft.com/apiproxy/mtp/huntingService/documentation/TableDocumentation"


def parse_args():
    parser = argparse.ArgumentParser(
        description="Extract Defender XDR Advanced Hunting ActionTypes into a combined action-types.json."
    )
    parser.add_argument("--session-cookie", required=True,
                        help="The 'sccauth' cookie value from an active security.microsoft.com session.")
    parser.add_argument("--xsrf-token", required=True,
                        help="The 'XSRF-TOKEN' cookie value (URL-encoded copy is fine, it is decoded for the header).")
    parser.add_argument("--tenant-id", required=True, help="Your Entra ID tenant GUID.")
    parser.add_argument("--output", default="./action-types.json",
                        help="Flat output file path (one object per ActionType). Default: ./action-types.json")
    parser.add_argument("--output-grouped", default="./action-types-grouped.json",
                        help="Grouped output file path (ActionTypes grouped per table). Default: ./action-types-grouped.json")
    parser.add_argument("--tables", nargs="*", default=None,
                        help="Optional list of specific table names. If omitted, pulls ALL known tables.")
    return parser.parse_args()


def main():
    args = parse_args()
    target_tables = args.tables if args.tables else ALL_TABLES

    decoded_xsrf = urllib.parse.unquote(args.xsrf_token) or args.xsrf_token

    session = requests.Session()
    session.cookies.set("sccauth", args.session_cookie, domain="security.microsoft.com", path="/")
    session.cookies.set("XSRF-TOKEN", args.xsrf_token, domain="security.microsoft.com", path="/")

    headers = {
        "accept": "application/json, text/plain, */*",
        "accept-language": "en-us",
        "x-xsrf-token": decoded_xsrf,
        "tenant-id": args.tenant_id,
    }

    print("\n=== Defender XDR ActionType Extractor ===")
    print(f"Target: {len(target_tables)} tables")
    print(f"Output: {args.output}\n")

    all_action_types = []
    failed_tables = []

    for index, table in enumerate(target_tables, start=1):
        pct = round(index / len(target_tables) * 100)
        print(f"[{index}/{len(target_tables)}] ({pct}%) {table}... ", end="")

        try:
            resp = session.get(f"{BASE_URL}/{table}", headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            action_types = data.get("ActionTypes") or []

            for at in action_types:
                all_action_types.append({
                    "Table": table,
                    "Name": at.get("Name"),
                    "Description": at.get("Description"),
                })

            print(f"{len(action_types)} ActionTypes")

            # Bail early if the first table returns nothing (likely an auth failure).
            if index == 1 and not action_types:
                fields = data.get("Fields") or []
                if not fields:
                    print("\n[!] First table returned no data - authentication likely failed.")
                    print("    Verify your sccauth and XSRF-TOKEN cookies are fresh.")
                    print("    Refresh the portal page and re-copy both cookies.\n")
                    sys.exit(1)
        except Exception as exc:  # noqa: BLE001
            print(f"FAILED - {exc}")
            failed_tables.append(table)

        time.sleep(0.3)

    if not all_action_types:
        print("\nNo ActionTypes retrieved. Exiting.")
        sys.exit(1)

    with open(args.output, "w", encoding="utf-8") as fh:
        json.dump(all_action_types, fh, indent=2, ensure_ascii=False)

    grouped = {}
    for at in all_action_types:
        grouped.setdefault(at["Table"], []).append({
            "Name": at["Name"],
            "Description": at["Description"],
        })

    with open(args.output_grouped, "w", encoding="utf-8") as fh:
        json.dump(grouped, fh, indent=2, ensure_ascii=False)

    print("\n=== Summary ===")
    print(f"Total ActionTypes: {len(all_action_types)}")
    print(f"Tables with ActionTypes: {len(grouped)}")
    if failed_tables:
        print(f"Failed tables:     {', '.join(failed_tables)}")
    print(f"\nWrote: {args.output}")
    print(f"Wrote: {args.output_grouped}")
    print("Done!")


if __name__ == "__main__":
    main()
