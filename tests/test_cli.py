"""Tests for CLI interface with path-aware matching."""

import json
import shutil

import pytest

from sbomdiff.cli import format_package_display, main


class TestFormatPackageDisplay:
    """Test package key formatting for display."""

    def test_format_with_path(self):
        """Should include binary name when path is present."""
        key = ("stdlib", "/usr/bin/service-a")
        result = format_package_display(key)
        assert result == "stdlib (service-a)"

    def test_format_without_path(self):
        """Should return just the name when path is empty."""
        key = ("example-lib", "")
        result = format_package_display(key)
        assert result == "example-lib"

    def test_format_extracts_basename(self):
        """Should extract just the filename from full path."""
        key = ("mypackage", "/usr/local/bin/myservice")
        result = format_package_display(key)
        assert result == "mypackage (myservice)"

    def test_format_with_deep_path(self):
        """Should handle deeply nested paths."""
        key = ("lib", "/a/very/deeply/nested/path/to/binary")
        result = format_package_display(key)
        assert result == "lib (binary)"


class TestCLIIntegration:
    """Integration tests for CLI with path-aware matching."""

    def test_cli_detects_version_changes(
        self, cyclonedx_version_change_old, cyclonedx_version_change_new, capsys
    ):
        """CLI should detect and report version changes."""
        main(
            ["sbomdiff", cyclonedx_version_change_old, cyclonedx_version_change_new]
        )

        captured = capsys.readouterr()
        assert "[VERSION]" in captured.out
        assert "stdlib" in captured.out
        assert "Version changes:  2" in captured.out

    def test_cli_shows_binary_name(
        self, cyclonedx_version_change_old, cyclonedx_version_change_new, capsys
    ):
        """CLI should show binary name in parentheses for path-aware packages."""
        main(
            ["sbomdiff", cyclonedx_version_change_old, cyclonedx_version_change_new]
        )

        captured = capsys.readouterr()
        # Should show binary name from path
        assert "(myapp)" in captured.out or "(status)" in captured.out

    def test_cli_json_output_includes_path(
        self, cyclonedx_version_change_old, cyclonedx_version_change_new, temp_dir
    ):
        """JSON output should include path field for packages with location info."""
        output_file = str(temp_dir / "output.json")
        main(
            [
                "sbomdiff",
                "-f",
                "json",
                "-o",
                output_file,
                cyclonedx_version_change_old,
                cyclonedx_version_change_new,
            ]
        )

        with open(output_file) as f:
            output = json.load(f)

        # Should have differences
        assert len(output["differences"]) > 0
        # At least one difference should have a path
        paths_in_output = [d.get("path") for d in output["differences"]]
        assert any(p for p in paths_in_output)

    def test_cli_rejects_same_file(self, cyclonedx_single_package, capsys):
        """CLI should reject comparing the same file."""
        result = main(["sbomdiff", cyclonedx_single_package, cyclonedx_single_package])

        captured = capsys.readouterr()
        assert "Must specify different filenames" in captured.out
        assert result == -1

    def test_cli_no_changes_identical_content(
        self, cyclonedx_single_package, temp_dir, capsys
    ):
        """CLI should report no changes when comparing identical content."""
        copy_file = str(temp_dir / "copy.json")
        shutil.copy(cyclonedx_single_package, copy_file)

        result = main(["sbomdiff", cyclonedx_single_package, copy_file])

        captured = capsys.readouterr()
        assert "Version changes:  0" in captured.out
        assert result == 0  # No differences

    def test_cli_detects_duplicate_package_changes(
        self, cyclonedx_duplicate_names, temp_dir, capsys
    ):
        """CLI should detect changes in all instances of duplicate packages."""
        # Create a modified version with one stdlib updated
        with open(cyclonedx_duplicate_names) as f:
            sbom = json.load(f)

        # Change version of one stdlib instance
        sbom["components"][0]["version"] = "go1.25.7"

        new_file = str(temp_dir / "modified.json")
        with open(new_file, "w") as f:
            json.dump(sbom, f)

        main(["sbomdiff", cyclonedx_duplicate_names, new_file])

        captured = capsys.readouterr()
        assert "[VERSION]" in captured.out
        # Should detect the specific instance that changed
        assert "stdlib" in captured.out
        assert "Version changes:  1" in captured.out


class TestCLIWithDuplicatePackages:
    """Tests specifically for handling packages with duplicate names."""

    @pytest.fixture
    def sbom_with_five_stdlibs(self, temp_dir):
        """Create SBOM with 5 Go stdlib instances like real FIPS stemcell."""
        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "components": [
                {
                    "type": "library",
                    "name": "stdlib",
                    "version": "go1.25.6",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/app/bin/agent"},
                    ],
                },
                {
                    "type": "library",
                    "name": "stdlib",
                    "version": "go1.25.6",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/app/bin/gcs"},
                    ],
                },
                {
                    "type": "library",
                    "name": "stdlib",
                    "version": "go1.25.6",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/app/bin/s3"},
                    ],
                },
                {
                    "type": "library",
                    "name": "stdlib",
                    "version": "go1.25.6",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/app/bin/dav"},
                    ],
                },
                {
                    "type": "library",
                    "name": "stdlib",
                    "version": "go1.25.6",
                    "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                    "properties": [
                        {"name": "syft:location:0:path", "value": "/app/bin/azure"},
                    ],
                },
            ],
        }
        filepath = temp_dir / "five_stdlibs.json"
        filepath.write_text(json.dumps(sbom, indent=2))
        return str(filepath)

    def test_all_five_instances_preserved(self, sbom_with_five_stdlibs):
        """All 5 stdlib instances should be preserved in parsing."""
        from sbomdiff.cyclonedx_parser import CycloneDXParser

        parser = CycloneDXParser()
        packages = parser.parse(sbom_with_five_stdlibs)

        # Count stdlib entries
        stdlib_count = sum(1 for k in packages if k[0] == "stdlib")
        assert stdlib_count == 5

    def test_partial_update_detected(self, sbom_with_five_stdlibs, temp_dir, capsys):
        """Should detect when only some stdlib instances are updated."""
        # Create modified version where only 2 stdlibs are updated
        with open(sbom_with_five_stdlibs) as f:
            sbom = json.load(f)

        # Update gcs and s3 to go1.25.7
        sbom["components"][1]["version"] = "go1.25.7"
        sbom["components"][2]["version"] = "go1.25.7"

        new_file = str(temp_dir / "partial_update.json")
        with open(new_file, "w") as f:
            json.dump(sbom, f)

        main(["sbomdiff", sbom_with_five_stdlibs, new_file])

        captured = capsys.readouterr()
        assert "Version changes:  2" in captured.out
        assert "(gcs)" in captured.out
        assert "(s3)" in captured.out
