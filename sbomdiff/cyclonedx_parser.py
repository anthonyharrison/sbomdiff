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

    def _get_package_key(self, name, path):
        """Create a unique key for a package.

        Uses (name, path) tuple when path is available to handle packages
        that appear at multiple locations (e.g., Go stdlib in multiple binaries).
        Falls back to (name, "") when no path is present.

        Args:
            name: Package name
            path: File path where package is located

        Returns:
            Tuple of (name, path) for use as dictionary key
        """
        return (name, path) if path else (name, "")

    def parse_cyclonedx_json(self, sbom_file):
        """parses CycloneDX JSON SBOM extracting package name, version and license

        Returns a dictionary where keys are (name, path) tuples and values are
        [version, license] lists. This allows tracking the same package at
        multiple locations.
        """
        data = json.load(open(sbom_file))
        packages = {}
        # Check that valid CycloneDX JSON file is being processed
        if "components" in data:
            for d in data["components"]:
                if d["type"] in ["library", "application", "operating-system"]:
                    name = d["name"]
                    # Extract path from properties
                    path = ""
                    properties = d.get("properties", [])
                    for prop in properties:
                        prop_name = prop.get("name", "").lower()
                        # Look for properties with location/path semantics
                        if ("location" in prop_name and "path" in prop_name) or prop_name.endswith(":path"):
                            path = prop.get("value", "")
                            break
                    package_key = self._get_package_key(name, path)
                    version = d["version"] if "version" in d else "UNKNOWN"
                    license = "NOT FOUND"
                    license_data = None
                    # Multiple ways of defining license data
                    if "licenses" in d and len(d["licenses"]) > 0:
                        license_data = d["licenses"][0]
                    elif "evidence" in d:
                        if "licenses" in d["evidence"]:
                            license_data = d["evidence"]["licenses"]
                    if license_data is not None:
                        license = None
                        if "license" in license_data:
                            if "id" in license_data["license"]:
                                license = license_data["license"]["id"]
                            elif "name" in license_data["license"]:
                                license = license_data["license"]["name"]
                            elif "expression" in license_data["license"]:
                                license = license_data["license"]["expression"]
                        elif "expression" in license_data:
                            license = license_data["expression"]
                        if license is None:
                            license = "UNKNOWN"
                    if package_key not in packages:
                        packages[package_key] = [version, license]

        return packages

    def parse_cyclonedx_xml(self, sbom_file):
        """parses CycloneDX XML BOM file extracting package name, version and license

        Returns a dictionary where keys are (name, path) tuples and values are
        [version, license] lists. XML format typically doesn't include path info,
        so path will usually be empty.
        """
        packages = {}
        tree = ET.parse(sbom_file)
        # Find root element
        root = tree.getroot()
        # Extract schema
        schema = root.tag[: root.tag.find("}") + 1]
        for components in root.findall(schema + "components"):
            try:
                for component in components.findall(schema + "component"):
                    # Only application, library and operating-systems components
                    if component.attrib["type"] in [
                        "library",
                        "application",
                        "operating-system",
                    ]:
                        component_name = component.find(schema + "name")
                        if component_name is None:
                            raise KeyError(f"Could not find package in {component}")
                        name = component_name.text
                        if name is None:
                            raise KeyError(f"Could not find package in {component}")
                        # Extract path from properties
                        path = ""
                        properties = component.find(schema + "properties")
                        if properties is not None:
                            for prop in properties.findall(schema + "property"):
                                prop_name = prop.attrib.get("name", "").lower()
                                # Look for properties with location/path semantics
                                if ("location" in prop_name and "path" in prop_name) or prop_name.endswith(":path"):
                                    path = prop.text or ""
                                    break
                        package_key = self._get_package_key(name, path)
                        component_version = component.find(schema + "version")
                        if component_version is None:
                            version = "UNKNOWN"
                        else:
                            version = component_version.text
                        license = "NOT FOUND"
                        component_license = component.find(schema + "licenses")
                        if component_license is not None:
                            license_data = component_license.find(schema + "expression")
                            if license_data is not None:
                                license = license_data.text
                        if version is not None:
                            if package_key not in packages:
                                packages[package_key] = [version, license]
            except KeyError:
                pass

        return packages
