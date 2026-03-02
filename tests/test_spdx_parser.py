# SPDX-License-Identifier: Apache-2.0

"""Tests for SPDX parser with tuple-based package keys."""

import json

import pytest
import yaml

from sbomdiff.spdx_parser import SPDXParser


class TestSPDXParserPackageKey:
    """Test package key generation for SPDX parser."""

    def test_get_package_key_returns_tuple(self):
        """Should return (name, '') tuple for consistency with CycloneDX."""
        parser = SPDXParser()
        key = parser._get_package_key("example-package")
        assert key == ("example-package", "")

    def test_get_package_key_empty_path(self):
        """SPDX keys should always have empty path component."""
        parser = SPDXParser()
        key = parser._get_package_key("my-lib")
        name, path = key
        assert name == "my-lib"
        assert path == ""


class TestSPDXParserJSON:
    """Test SPDX JSON parsing with tuple keys."""

    @pytest.fixture
    def spdx_json_file(self, temp_dir):
        """Create a sample SPDX JSON file."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-sbom",
            "packages": [
                {
                    "name": "example-lib",
                    "versionInfo": "1.0.0",
                    "licenseConcluded": "MIT",
                },
                {
                    "name": "another-lib",
                    "versionInfo": "2.0.0",
                    "licenseConcluded": "Apache-2.0",
                },
            ],
        }
        filepath = temp_dir / "test.spdx.json"
        filepath.write_text(json.dumps(sbom, indent=2))
        return str(filepath)

    def test_parse_returns_tuple_keys(self, spdx_json_file):
        """All keys should be (name, path) tuples."""
        parser = SPDXParser()
        packages = parser.parse(spdx_json_file)

        for key in packages:
            assert isinstance(key, tuple)
            assert len(key) == 2
            name, path = key
            assert isinstance(name, str)
            assert path == ""  # SPDX doesn't have path info

    def test_parse_extracts_packages(self, spdx_json_file):
        """Should extract all packages correctly."""
        parser = SPDXParser()
        packages = parser.parse(spdx_json_file)

        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

    def test_parse_extracts_versions(self, spdx_json_file):
        """Should extract version information."""
        parser = SPDXParser()
        packages = parser.parse(spdx_json_file)

        version, _ = packages[("example-lib", "")]
        assert version == "1.0.0"

    def test_parse_extracts_licenses(self, spdx_json_file):
        """Should extract license information."""
        parser = SPDXParser()
        packages = parser.parse(spdx_json_file)

        _, license = packages[("example-lib", "")]
        assert license == "MIT"


class TestSPDXParserYAML:
    """Test SPDX YAML parsing with tuple keys."""

    @pytest.fixture
    def spdx_yaml_file(self, temp_dir):
        """Create a sample SPDX YAML file."""
        sbom = {
            "spdxVersion": "SPDX-2.3",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": "test-sbom",
            "packages": [
                {
                    "name": "yaml-lib",
                    "versionInfo": "3.0.0",
                    "licenseConcluded": "BSD-3-Clause",
                },
            ],
        }
        filepath = temp_dir / "test.spdx.yaml"
        filepath.write_text(yaml.dump(sbom))
        return str(filepath)

    def test_parse_yaml_returns_tuple_keys(self, spdx_yaml_file):
        """YAML parsing should also return tuple keys."""
        parser = SPDXParser()
        packages = parser.parse(spdx_yaml_file)

        assert len(packages) == 1
        assert ("yaml-lib", "") in packages


class TestSPDXParserTagValue:
    """Test SPDX TagValue parsing with tuple keys."""

    def test_parse_tag_returns_tuple_keys(self, spdx_tag_file):
        """TagValue parsing should return tuple keys."""
        parser = SPDXParser()
        packages = parser.parse(spdx_tag_file)

        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

    def test_parse_tag_extracts_versions(self, spdx_tag_file):
        """Should extract version information from TagValue."""
        parser = SPDXParser()
        packages = parser.parse(spdx_tag_file)

        version, _ = packages[("example-lib", "")]
        assert version == "1.0.0"

    def test_parse_tag_extracts_licenses(self, spdx_tag_file):
        """Should extract license information from TagValue."""
        parser = SPDXParser()
        packages = parser.parse(spdx_tag_file)

        _, license = packages[("example-lib", "")]
        assert license == "MIT"


class TestSPDXParserRDF:
    """Test SPDX RDF parsing with tuple keys."""

    def test_parse_rdf_returns_tuple_keys(self, spdx_rdf_file):
        """RDF parsing should return tuple keys."""
        parser = SPDXParser()
        packages = parser.parse(spdx_rdf_file)

        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

    def test_parse_rdf_extracts_versions(self, spdx_rdf_file):
        """Should extract version information from RDF."""
        parser = SPDXParser()
        packages = parser.parse(spdx_rdf_file)

        version, _ = packages[("example-lib", "")]
        assert version == "1.0.0"

    def test_parse_rdf_extracts_licenses(self, spdx_rdf_file):
        """Should extract license information from RDF."""
        parser = SPDXParser()
        packages = parser.parse(spdx_rdf_file)

        _, license = packages[("example-lib", "")]
        assert license == "MIT"


class TestSPDXParserXML:
    """Test SPDX XML parsing with tuple keys."""

    def test_parse_xml_returns_tuple_keys(self, spdx_xml_file):
        """XML parsing should return tuple keys."""
        parser = SPDXParser()
        packages = parser.parse(spdx_xml_file)

        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

    def test_parse_xml_extracts_versions(self, spdx_xml_file):
        """Should extract version information from XML."""
        parser = SPDXParser()
        packages = parser.parse(spdx_xml_file)

        version, _ = packages[("example-lib", "")]
        assert version == "1.0.0"

    def test_parse_xml_extracts_licenses(self, spdx_xml_file):
        """Should extract license information from XML."""
        parser = SPDXParser()
        packages = parser.parse(spdx_xml_file)

        _, license = packages[("example-lib", "")]
        assert license == "MIT"


class TestSPDXParserCrossFormat:
    """Test that SPDX and CycloneDX key formats are compatible."""

    def test_key_format_matches_cyclonedx(self, temp_dir):
        """SPDX keys should be compatible with CycloneDX keys for cross-format comparison."""
        from sbomdiff.cyclonedx_parser import CycloneDXParser

        # Create SPDX file
        spdx_sbom = {
            "packages": [
                {
                    "name": "shared-lib",
                    "versionInfo": "1.0.0",
                    "licenseConcluded": "MIT",
                },
            ],
        }
        spdx_path = temp_dir / "test.spdx.json"
        spdx_path.write_text(json.dumps(spdx_sbom, indent=2))

        # Create CycloneDX file without path
        cdx_sbom = {
            "components": [
                {
                    "type": "library",
                    "name": "shared-lib",
                    "version": "2.0.0",
                    "licenses": [{"license": {"id": "MIT"}}],
                },
            ],
        }
        cdx_path = temp_dir / "test.json"
        cdx_path.write_text(json.dumps(cdx_sbom, indent=2))

        # Parse both
        spdx = SPDXParser()
        cdx = CycloneDXParser()
        spdx_packages = spdx.parse(str(spdx_path))
        cdx_packages = cdx.parse(str(cdx_path))

        # Keys should be in the same format
        spdx_key = list(spdx_packages.keys())[0]
        cdx_key = list(cdx_packages.keys())[0]

        assert type(spdx_key) == type(cdx_key)
        assert len(spdx_key) == len(cdx_key)
        # Same package name should create matching keys
        assert spdx_key == cdx_key
