# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json
import re

import defusedxml.ElementTree as ET
import yaml


class SPDXParser:
    def __init__(self):
        pass

    def parse(self, sbom_file):
        """parses SPDX BOM file extracting package name, version and license"""
        if sbom_file.endswith(".spdx"):
            return self.parse_spdx_tag(sbom_file)
        elif sbom_file.endswith(".spdx.json"):
            return self.parse_spdx_json(sbom_file)
        elif sbom_file.endswith(".spdx.rdf"):
            return self.parse_spdx_rdf(sbom_file)
        elif sbom_file.endswith(".spdx.xml"):
            return self.parse_spdx_xml(sbom_file)
        elif sbom_file.endswith((".spdx.yaml", "spdx.yml")):
            return self.parse_spdx_yaml(sbom_file)
        else:
            return {}

    def parse_spdx_tag(self, sbom_file):
        """parses SPDX tag value BOM file extracting package name, version and license"""
        with open(sbom_file) as f:
            lines = f.readlines()
        packages = {}
        package = ""
        for line in lines:
            line_elements = line.split(":")
            if line_elements[0] == "PackageName":
                package = line_elements[1].strip().rstrip("\n")
                version = None
            if line_elements[0] == "PackageVersion":
                version = line_elements[1].strip().rstrip("\n")
                version = version.split("-")[0]
                version = version.split("+")[0]
            if line_elements[0] == "PackageLicenseConcluded":
                license = line_elements[1].strip().rstrip("\n")
                if package not in packages and version is not None:
                    packages[package] = [version, license]

        return packages

    def parse_spdx_json(self, sbom_file):
        """parses SPDX JSON BOM file extracting package name, version and license"""
        data = json.load(open(sbom_file))
        packages = {}
        for d in data["packages"]:
            package = d["name"]
            try:
                version = d["versionInfo"]
                license = d["licenseConcluded"]
                if package not in packages:
                    packages[package] = [version, license]
            except KeyError as e:
                pass

        return packages

    def parse_spdx_rdf(self, sbom_file):
        """parses SPDX RDF BOM file extracting package name, version and license"""
        with open(sbom_file) as f:
            lines = f.readlines()
        packages = {}
        package = ""
        for line in lines:
            try:
                if line.strip().startswith("<spdx:name>"):
                    stripped_line = line.strip().rstrip("\n")
                    package_match = re.search(
                        "<spdx:name>(.+?)</spdx:name>", stripped_line
                    )
                    if not package_match:
                        raise KeyError(f"Could not find package in {stripped_line}")
                    package = package_match.group(1)
                    version = None
                elif line.strip().startswith("<spdx:versionInfo>"):
                    stripped_line = line.strip().rstrip("\n")
                    version_match = re.search(
                        "<spdx:versionInfo>(.+?)</spdx:versionInfo>", stripped_line
                    )
                    if not version_match:
                        raise KeyError(f"Could not find version in {stripped_line}")
                    version = version_match.group(1)
                    # To handle case where license appears before version
                    if package not in packages and license is not None:
                        packages[package] = [version, license]
                        version = None
                elif line.strip().startswith("<spdx:licenseConcluded"):
                    stripped_line = line.strip().rstrip("\n")
                    # Assume license tag is on a single line
                    license_match = re.search(
                        "<spdx:licenseConcluded rdf:resource=(.+?)/>", stripped_line
                    )
                    if license_match is None:
                        license = "NOT FOUND"
                    else:
                        license = license_match.group(1)
                        if license.startswith("\"http://spdx.org/licenses/"):
                            # SPDX license identifier. Extract last part of url
                            license = license.split("/")[-1]
                            license=license[:-1] # Remove trialing "
                        if "#" in license:
                            # Extract last part of url after # e.g. http://spdx.org/rdf/terms#noassertion
                            license = license.split("#")[-1]
                            license=license[:-1].upper() # Remove trialing " and capitalise
                    # To handle case where license appears before version
                    if package not in packages and version is not None:
                        packages[package] = [version, license]
                        license = None
            except KeyError as e:
                pass

        return packages

    def parse_spdx_yaml(self, sbom_file):
        """parses SPDX YAML BOM file extracting package name, version and license"""
        data = yaml.safe_load(open(sbom_file))

        packages = {}
        for d in data["packages"]:
            package = d["name"]
            try:
                version = d["versionInfo"]
                license = d["licenseConcluded"]
                if package not in packages:
                    packages[package] = [version, license]
            except KeyError as e:
                pass

        return packages

    def parse_spdx_xml(self, sbom_file):
        """parses SPDX XML BOM file extracting package name, version and license"""
        # XML is experimental in SPDX 2.3
        packages = {}
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]

        for component in root.findall(schema + "packages"):
            try:
                package_match = component.find(schema + "name")
                if package_match is None:
                    raise KeyError(f"Could not find package in {component}")
                package = package_match.text
                if package is None:
                    raise KeyError(f"Could not find package in {component}")
                version_match = component.find(schema + "versionInfo")
                if version_match is None:
                    raise KeyError(f"Could not find version in {component}")
                version = version_match.text
                if version is None:
                    raise KeyError(f"Could not find version in {component}")
                component_license = component.find(schema + "licenseConcluded")
                if component_license is None:
                    license = "NOT FOUND"
                else:
                    license = component_license.text

                if version is not None:
                    if package not in packages:
                        packages[package] = [version, license]

            except KeyError as e:
                pass

        return packages
