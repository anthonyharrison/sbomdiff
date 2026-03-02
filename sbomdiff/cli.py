# Copyright (C) 2023 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0
# Copyright 2024 Hewlett Packard Enterprise Development LP (comments for added material tagged HPE)

import argparse
import pathlib
import sys
import textwrap
from collections import ChainMap

from lib4sbom.data.package import SBOMPackage
from lib4sbom.output import SBOMOutput
from lib4sbom.parser import SBOMParser

from sbomdiff.version import VERSION


def format_package_display(package_key):
    """Format package key for display.

    Package keys are tuples of (name, path). When path is present,
    show the binary name in parentheses for context.

    Args:
        package_key: Tuple of (name, path)

    Returns:
        Formatted string like "name" or "name (binary)"
    """
    name, path = package_key
    if path:
        # Extract filename from path
        binary = path.rsplit("/", 1)[-1]
        return f"{name} ({binary})"
    return name


def process_packages(package_list):
    packages = {}
    thepackage = SBOMPackage()
    for package in package_list:
        thepackage.initialise()
        thepackage.copy_package(package)
        name = thepackage.get_name()
        version = thepackage.get_value("version")
        name = thepackage.get_name()
        license = thepackage.get_value("licenseconcluded")
        if license is None:
            license = "UNKNOWN"
        checksums = thepackage.get_value("checksum")
        properties = thepackage.get_value("properties")
        # Special handling for Syft SBOMs
        path = ""
        properties = thepackage.get_value("properties")
        if properties is not None:
            for prop in properties:
                prop_name = prop.get("name", "").lower()
                # Look for properties with location/path semantics
                if (
                    "location" in prop_name and "path" in prop_name
                ) or prop_name.endswith(":path"):
                    path = prop.get("value", "")
                    break
        package_key = (name, path) if path else (name, "")
        if package_key not in packages and version is not None:
            packages[package_key] = [version, license, checksums]
    return packages


# CLI processing


def main(argv=None):
    argv = argv or sys.argv
    parser = argparse.ArgumentParser(
        prog="sbomdiff",
        description=textwrap.dedent("""
            SBOMDiff compares two Software Bill of Materials and
            reports the differences.
            """),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "--sbom",
        action="store",
        default="auto",
        choices=["auto", "spdx", "cyclonedx"],
        help="specify type of sbom to compare (default: auto)",
    )
    input_group.add_argument(
        "--exclude-license",
        action="store_true",
        help="suppress reporting differences in the license of components",
    )
    input_group.add_argument(
        "--checksum",
        action="store",
        choices=[
            "MD5",
            "SHA1",
            "SHA256",
            "SHA384",
            "SHA512",
            "SHA3-256",
            "SHA3-384",
            "SHA3-512",
            "BLAKE2b-256",
            "BLAKE2b-384",
            "BLAKE2b-512",
            "BLAKE3",
        ],
        default="SHA256",
        help="specify checksum algorithm to use in comparison (default: SHA256)",
    )
    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="show debug information",
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )
    output_group.add_argument(
        "-f",
        "--format",
        action="store",
        default="text",
        choices=["text", "json", "yaml"],
        help="specify format of output file (default: text)",
    )
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    parser.add_argument("FILE1", help="first SBOM file")
    parser.add_argument("FILE2", help="second SBOM file")

    defaults = {
        "output_file": "",
        "sbom": "auto",
        "exclude_license": False,
        "debug": False,
        "format": "text",
        "checksum": "SHA256"
    }
    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters
    if args["FILE1"] != args["FILE2"]:
        # Check both files exist
        file_found = True
        if not pathlib.Path(args["FILE1"]).exists():
            print(f"{args['FILE1']} does not exist")
            file_found = False
        if not pathlib.Path(args["FILE2"]).exists():
            print(f"{args['FILE2']} does not exist")
            file_found = False
        if not file_found:
            return -1
    else:
        # Same filename specified
        print("Must specify different filenames")
        return -1

    sbom_parser = SBOMParser(sbom_type=args["sbom"])
    # Extract packages frome ach file
    sbom_parser.parse_file(args["FILE1"])
    packages1 = process_packages(sbom_parser.get_packages())
    file1_type = sbom_parser.get_type()
    sbom_parser.parse_file(args["FILE2"])
    packages2 = process_packages(sbom_parser.get_packages())
    file2_type = sbom_parser.get_type()

    if args["debug"]:
        print("SBOM type", args["sbom"])
        print("Output file", args["output_file"])
        print("Format", args["format"])
        print("SBOM File1", args["FILE1"])
        print("SBOM File1 - type", file1_type)
        print("SBOM File1 - packages", len(packages1))
        print("SBOM File2", args["FILE2"])
        print("SBOM File2 - type", file2_type)
        print("SBOM File2 - packages", len(packages2))
        print("Exclude Licences", args["exclude_license"])
        print("Checksum algorithm", args["checksum"])

    # Keep count of differences
    version_changes = 0
    new_packages = 0
    removed_packages = 0
    license_changes = 0
    checksum_changes = 0

    sbom_out = SBOMOutput(args["output_file"], args["format"])

    if args["format"] != "text":
        diff_doc = []

    for package_key in packages1:
        package_info = dict()
        package_display = format_package_display(package_key)
        package_name, package_path = package_key
        if package_key in packages2:
            # Compare values for common package
            version1, license1, checksums1 = packages1[package_key]
            version2, license2, checksums2 = packages2[package_key]
            version1 = version1.upper()
            version2 = version2.upper()
            package_info["package"] = package_name
            if package_path:
                package_info["path"] = package_path
            diff_record = False
            if version1 != version2:
                if len(version1) == 0:
                    version1 = "UNKNOWN"
                if len(version2) == 0:
                    version2 = "UNKNOWN"
                if args["format"] == "text":
                    sbom_out.send_output(
                        f"[VERSION] {package_display}: "
                        f"Version changed from {version1} to {version2}"
                    )
                package_info["status"] = "change"
                version_info = dict()
                version_info["from"] = version1
                version_info["to"] = version2
                package_info["version"] = version_info
                version_changes += 1
                diff_record = True
            if not args["exclude_license"] and license1 != license2:
                if args["format"] == "text":
                    sbom_out.send_output(
                        f"[LICENSE] {package_display}: "
                        f"License changed from {license1} to {license2}"
                    )
                package_info["status"] = "change"
                license_info = dict()
                license_info["from"] = license1
                license_info["to"] = license2
                package_info["license"] = license_info
                license_changes += 1
                diff_record = True
            if checksums1 is not None and checksums2 is not None:
                # compare checksums
                value1 = value2 = None
                for checksum in checksums1:
                    if checksum[0] == args["checksum"]:
                        value1 = checksum[1]
                        break
                for checksum in checksums2:
                    if checksum[0] == args["checksum"]:
                        value2 = checksum[1]
                        break
                if value1 is not None and value2 is not None:
                    if value1 != value2:
                        if args["format"] == "text":
                            sbom_out.send_output(
                                f"[CHECKSUM] {package_display}: "
                                f"Checksum changed from {value1} to {value2}"
                            )
                        package_info["status"] = "change"
                        checksum_info = dict()
                        checksum_info["from"] = value1
                        checksum_info["to"] = value2
                        package_info["checksum"] = checksum_info
                        checksum_changes += 1
                        diff_record = True
        else:
            # Package must have been removed
            version1, license1, _ = packages1[package_key]
            version1 = version1.upper()
            package_info["package"] = package_name
            if package_path:
                package_info["path"] = package_path
            if len(version1) == 0:
                version1 = "UNKNOWN"
            if args["format"] == "text":
                sbom_out.send_output(
                    f"[REMOVED] {package_display}: (Version {version1})"
                )
            package_info["status"] = "remove"
            version_info = dict()
            version_info["from"] = version1
            package_info["version"] = version_info
            removed_packages += 1
            diff_record = True
        if args["format"] != "text" and diff_record:
            diff_doc.append(package_info)
    # Check for any new packages
    for package_key in packages2:
        if package_key not in packages1:
            package_display = format_package_display(package_key)
            package_name, package_path = package_key
            version2, license2, _ = packages2[package_key]
            version2 = version2.upper()
            if len(version2) == 0:
                version2 = "UNKNOWN"
            if args["format"] == "text":
                sbom_out.send_output(
                    f"[ADDED  ] {package_display}: (Version {version2}) (License {license2})"
                )  # HPE Added license to text output
            else:
                package_info = dict()
                package_info["package"] = package_name
                if package_path:
                    package_info["path"] = package_path
                package_info["status"] = "add"
                version_info = dict()
                version_info["from"] = version2
                package_info["version"] = version_info
                license_info = dict()  # HPE - Adding license dictionary
                license_info["to"] = license2  # HPE - Adding the new license
                package_info["license"] = (
                    license_info  # HPE - Adding license_info to package_info
                )
                diff_doc.append(package_info)
            new_packages += 1
    if args["format"] == "text":
        sbom_out.send_output("\nSummary\n-------")
        sbom_out.send_output(f"Version changes:  {version_changes}")
        if not args["exclude_license"]:
            sbom_out.send_output(f"License changes:  {license_changes}")
        sbom_out.send_output(f"Removed packages: {removed_packages}")
        sbom_out.send_output(f"New packages:     {new_packages}")
        sbom_out.send_output(f"Checksum changes: {checksum_changes}")

    if args["format"] != "text":
        json_doc = {}
        tool = dict()
        tool["name"] = "sbomdiff"
        tool["version"] = VERSION
        json_doc["tool"] = tool
        json_doc["file_1"] = args["FILE1"]
        json_doc["file_2"] = args["FILE2"]
        json_doc["differences"] = diff_doc
        summary = dict()
        summary["version_changes"] = version_changes
        summary["new_packages"] = new_packages
        summary["removed_packages"] = removed_packages
        if not args["exclude_license"]:
            summary["license_changes"] = license_changes
        summary["checksum_changes"] = checksum_changes
        json_doc["summary"] = summary
        sbom_out.generate_output(json_doc)

    # Return code indicates if any differences have been detected
    if (version_changes or license_changes or removed_packages or new_packages or checksum_changes) != 0:
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())
