# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from sbomdiff.cyclonedx_parser import CycloneDXParser
from sbomdiff.output import SBOMOutput
from sbomdiff.spdx_parser import SPDXParser
from sbomdiff.version import VERSION

# CLI processing

def main(argv=None):

    argv = argv or sys.argv
    parser = argparse.ArgumentParser(
        prog="sbomdiff",
        description=textwrap.dedent(
            """
            SBOMDiff compares two Software Bill of Materials and
            reports the differences.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "--sbom",
        action="store",
        default="auto",
        choices=["auto", "spdx", "cyclonedx"],
        help="specify type of sbom to compare (default: auto)",
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
    parser.add_argument("-V", "--version", action="version", version=VERSION)

    parser.add_argument("FILE1", help="first SBOM file")
    parser.add_argument("FILE2", help="second SBOM file")

    defaults = {
        "output_file": "",
        "sbom": "auto",
        "debug": False,
    }
    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    spdx = SPDXParser()
    cyclonedx = CycloneDXParser()

    if args["sbom"] == "spdx":
        file1_type = file2_type = "SPDX"
        packages1 = spdx.parse(args["FILE1"])
        packages2 = spdx.parse(args["FILE2"])
    elif args["sbom"] == "cyclonedx":
        file1_type = file2_type = "CYCLONEDX"
        packages1 = cyclonedx.parse(args["FILE1"])
        packages2 = cyclonedx.parse(args["FILE2"])
    else:
        # Work out the SBOM type for each file
        packages1 = spdx.parse(args["FILE1"])
        file1_type = "SPDX"
        if len(packages1) == 0:
            packages1 = cyclonedx.parse(args["FILE1"])
            file1_type = "CYCLONEDX"
        packages2 = spdx.parse(args["FILE2"])
        file2_type = "SPDX"
        if len(packages2) == 0:
            file2_type = "CYCLONEDX"
            packages2 = cyclonedx.parse(args["FILE2"])

    if args["debug"]:
        print("SBOM type", args["sbom"])
        print("Output file", args["output_file"])
        print("SBOM File1", args["FILE1"])
        print("SBOM File1 - type", file1_type)
        print("SBOM File1 - packages", len(packages1))
        print("SBOM File2", args["FILE2"])
        print("SBOM File2 - type", file2_type)
        print("SBOM File2 - packages", len(packages2))

    # Keep count of differences
    version_changes = 0
    new_packages = 0
    removed_packages = 0
    license_changes = 0

    sbom_out = SBOMOutput(args["output_file"])

    for package in packages1:
        if package in packages2:
            # Compare values for common package
            version1, license1 = packages1[package]
            version2, license2 = packages2[package]
            if version1 != version2:
                sbom_out.send_output(f"[VERSION] {package}: Version changed from {version1} to {version2}")
                version_changes += 1
            if license1 != license2:
                sbom_out.send_output(f"[LICENSE] {package}: License changed from {license1} to {license2}")
                license_changes += 1
        else:
            # Package must have been removed
            version1, license1 = packages1[package]
            sbom_out.send_output(f"[REMOVED] {package}: (Version {version1})")
            removed_packages += 1
    # Check for any new packages
    for package in packages2:
        if package not in packages1:
            version2, license2 = packages2[package]
            sbom_out.send_output(f"[ADDED  ] {package}: (Version {version2})")
            new_packages += 1
    sbom_out.send_output("\nSummary\n-------")
    sbom_out.send_output(f"Version changes:  {version_changes}")
    sbom_out.send_output(f"License changes:  {license_changes}")
    sbom_out.send_output(f"Removed packages: {removed_packages}")
    sbom_out.send_output(f"New packages:     {new_packages}")

    sbom_out.close_output()

    # Return code indicates if any differences have been detected
    if (version_changes or license_changes or removed_packages or new_packages) != 0:
        return 1

    return 0

if __name__ == "__main__":
    sys.exit(main())
