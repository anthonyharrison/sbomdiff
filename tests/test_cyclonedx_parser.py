# SPDX-License-Identifier: Apache-2.0

"""Tests for CycloneDX parser with path-aware matching."""

from sbomdiff.cyclonedx_parser import CycloneDXParser


class TestCycloneDXParserPackageKey:
    """Test package key generation."""

    def test_get_package_key_with_path(self):
        """Should return (name, path) tuple when path is provided."""
        parser = CycloneDXParser()
        key = parser._get_package_key("stdlib", "/usr/local/bin/app")
        assert key == ("stdlib", "/usr/local/bin/app")

    def test_get_package_key_without_path(self):
        """Should return (name, '') tuple when path is empty."""
        parser = CycloneDXParser()
        key = parser._get_package_key("example-lib", "")
        assert key == ("example-lib", "")

    def test_get_package_key_with_none_path(self):
        """Should handle None path gracefully."""
        parser = CycloneDXParser()
        # When path is falsy (empty string or None), should return (name, "")
        key = parser._get_package_key("example-lib", None)
        assert key == ("example-lib", "")


class TestCycloneDXParserJSON:
    """Test JSON parsing with path-aware matching."""

    def test_parse_single_package(self, cyclonedx_single_package):
        """Should parse single package without path."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_single_package)

        assert len(packages) == 1
        # Key should be (name, "") when no path
        assert ("example-lib", "") in packages
        version, license = packages[("example-lib", "")]
        assert version == "1.0.0"
        assert license == "MIT"

    def test_parse_packages_with_paths(self, cyclonedx_with_path):
        """Should parse packages with path properties."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_with_path)

        assert len(packages) == 2
        # Both stdlib entries should be present with different paths
        assert ("stdlib", "/usr/bin/service-a") in packages
        assert ("stdlib", "/usr/bin/service-b") in packages

    def test_parse_duplicate_names_different_versions(self, cyclonedx_duplicate_names):
        """Should preserve all instances of duplicate package names."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_duplicate_names)

        assert len(packages) == 3
        # Each stdlib at different path should have its own entry
        assert ("stdlib", "/app/bin/service-a") in packages
        assert ("stdlib", "/app/bin/service-b") in packages
        assert ("stdlib", "/app/bin/service-c") in packages

        # Verify versions are preserved correctly
        assert packages[("stdlib", "/app/bin/service-a")][0] == "go1.25.6"
        assert packages[("stdlib", "/app/bin/service-b")][0] == "go1.24.2"
        assert packages[("stdlib", "/app/bin/service-c")][0] == "go1.25.7"

    def test_parse_packages_without_paths(self, cyclonedx_no_path):
        """Should parse packages without path properties using empty path."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_no_path)

        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

    def test_keys_are_tuples(self, cyclonedx_single_package):
        """All keys should be (name, path) tuples."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_single_package)

        for key in packages:
            assert isinstance(key, tuple)
            assert len(key) == 2
            name, path = key
            assert isinstance(name, str)
            assert isinstance(path, str)


class TestCycloneDXParserIntegration:
    """Integration tests for complete parsing workflow."""

    def test_comparison_detects_version_changes(
        self, cyclonedx_version_change_old, cyclonedx_version_change_new
    ):
        """Should detect version changes when comparing two SBOMs."""
        parser = CycloneDXParser()
        old_packages = parser.parse(cyclonedx_version_change_old)
        new_packages = parser.parse(cyclonedx_version_change_new)

        # Find version changes
        changes = []
        for key in old_packages:
            if key in new_packages:
                old_version = old_packages[key][0]
                new_version = new_packages[key][0]
                if old_version != new_version:
                    changes.append((key, old_version, new_version))

        assert len(changes) == 2
        # Verify stdlib version change was detected
        stdlib_change = [c for c in changes if c[0][0] == "stdlib"][0]
        assert stdlib_change[1] == "go1.25.6"
        assert stdlib_change[2] == "go1.25.7"

        # Verify libc version change was detected
        libc_change = [c for c in changes if c[0][0] == "libc"][0]
        assert libc_change[1] == "2.35-0ubuntu3.12"
        assert libc_change[2] == "2.35-0ubuntu3.13"


class TestCycloneDXParserXML:
    """Test XML parsing with path-aware matching."""

    def test_parse_xml_with_paths(self, cyclonedx_xml_with_path):
        """Should parse XML format with path properties."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_xml_with_path)

        assert len(packages) == 2
        # Both stdlib entries should be present with different paths
        assert ("stdlib", "/usr/bin/service-a") in packages
        assert ("stdlib", "/usr/bin/service-b") in packages

    def test_parse_xml_extracts_versions(self, cyclonedx_xml_with_path):
        """Should extract version information from XML."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_xml_with_path)

        version, _ = packages[("stdlib", "/usr/bin/service-a")]
        assert version == "go1.25.6"

    def test_parse_xml_extracts_licenses(self, cyclonedx_xml_with_path):
        """Should extract license information from XML."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_xml_with_path)

        _, license = packages[("stdlib", "/usr/bin/service-a")]
        assert license == "BSD-3-Clause"

    def test_parse_xml_without_paths(self, cyclonedx_xml_without_path):
        """Should parse XML without path properties (typical case)."""
        parser = CycloneDXParser()
        packages = parser.parse(cyclonedx_xml_without_path)

        # Should have 2 packages with empty paths
        assert len(packages) == 2
        assert ("example-lib", "") in packages
        assert ("another-lib", "") in packages

        # Verify version extraction
        version, _ = packages[("example-lib", "")]
        assert version == "1.0.0"

        # Verify license extraction  
        _, license = packages[("example-lib", "")]
        assert license == "MIT"

