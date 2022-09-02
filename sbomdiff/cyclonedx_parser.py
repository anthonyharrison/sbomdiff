# Copyright (C) 2022 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import json

import defusedxml.ElementTree as ET


class CycloneDXParser:
    def __init__(self):
        pass

    def parse(self, sbom_file):
        """parses CycloneDX BOM file extracting package name, version and license"""
        if sbom_file.endswith("json"):
            return self.parse_cyclonedx_json(sbom_file)
        elif sbom_file.endswith(".xml"):
            return self.parse_cyclonedx_xml(sbom_file)
        else:
            return {}

    def parse_cyclonedx_json(self, sbom_file):
        """parses CycloneDX JSON BOM file extracting package name, version and license"""
        data = json.load(open(sbom_file))
        packages = {}
        for d in data["components"]:
            if d["type"] in ["library", "application"]:
                package = d["name"]
                version = d["version"]
                if "license" in d:
                    license = d["license"]
                else:
                    license = "NOT FOUND"
                if package not in packages:
                    packages[package] = [version, license]

        return packages

    def parse_cyclonedx_xml(self, sbom_file):
        """parses CycloneDX XML BOM file extracting package name, version and license"""
        packages = {}
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        for components in root.findall(schema + "components"):
            try:
                for component in components.findall(schema + "component"):
                    # Only for application and library components
                    if component.attrib["type"] in ["library", "application"]:
                        component_name = component.find(schema + "name")
                        if component_name is None:
                            raise KeyError(f"Could not find package in {component}")
                        package = component_name.text
                        if package is None:
                            raise KeyError(f"Could not find package in {component}")
                        component_version = component.find(schema + "version")
                        if component_version is None:
                            raise KeyError(f"Could not find version in {component}")
                        version = component_version.text
                        component_license = component.find(schema + "license")
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
