# SPDX-License-Identifier: Apache-2.0

"""Pytest fixtures for sbomdiff tests.

Provides reusable SBOM test files in various formats for testing
path-aware package matching functionality.
"""

import json
import tempfile
from pathlib import Path

import pytest


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def cyclonedx_single_package(temp_dir):
    """CycloneDX SBOM with a single package (no path info)."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "example-lib",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            }
        ],
    }
    filepath = temp_dir / "single.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_with_path(temp_dir):
    """CycloneDX SBOM with syft path properties."""
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
                    {"name": "syft:package:type", "value": "go-module"},
                    {
                        "name": "syft:location:0:path",
                        "value": "/usr/bin/service-a",
                    },
                ],
            },
            {
                "type": "library",
                "name": "stdlib",
                "version": "go1.25.6",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {"name": "syft:package:type", "value": "go-module"},
                    {
                        "name": "syft:location:0:path",
                        "value": "/usr/bin/service-b",
                    },
                ],
            },
        ],
    }
    filepath = temp_dir / "with_path.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_duplicate_names(temp_dir):
    """CycloneDX SBOM with duplicate package names at different paths."""
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
                    {
                        "name": "syft:location:0:path",
                        "value": "/app/bin/service-a",
                    },
                ],
            },
            {
                "type": "library",
                "name": "stdlib",
                "version": "go1.24.2",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": "/app/bin/service-b",
                    },
                ],
            },
            {
                "type": "library",
                "name": "stdlib",
                "version": "go1.25.7",
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": "/app/bin/service-c",
                    },
                ],
            },
        ],
    }
    filepath = temp_dir / "duplicates.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_version_change_old(temp_dir):
    """CycloneDX SBOM - old version for comparison."""
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
                    {
                        "name": "syft:location:0:path",
                        "value": "/app/bin/myapp",
                    },
                ],
            },
            {
                "type": "library",
                "name": "libc",
                "version": "2.35-0ubuntu3.12",
                "licenses": [{"license": {"id": "GPL-2.0"}}],
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": "/var/lib/dpkg/status",
                    },
                ],
            },
        ],
    }
    filepath = temp_dir / "old.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_version_change_new(temp_dir):
    """CycloneDX SBOM - new version for comparison."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "stdlib",
                "version": "go1.25.7",  # Version changed
                "licenses": [{"license": {"id": "BSD-3-Clause"}}],
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": "/app/bin/myapp",
                    },
                ],
            },
            {
                "type": "library",
                "name": "libc",
                "version": "2.35-0ubuntu3.13",  # Version changed
                "licenses": [{"license": {"id": "GPL-2.0"}}],
                "properties": [
                    {
                        "name": "syft:location:0:path",
                        "value": "/var/lib/dpkg/status",
                    },
                ],
            },
        ],
    }
    filepath = temp_dir / "new.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_no_path(temp_dir):
    """CycloneDX SBOM without path properties."""
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "components": [
            {
                "type": "library",
                "name": "example-lib",
                "version": "1.0.0",
                "licenses": [{"license": {"id": "MIT"}}],
            },
            {
                "type": "library",
                "name": "another-lib",
                "version": "2.0.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}],
            },
        ],
    }
    filepath = temp_dir / "no_path.json"
    filepath.write_text(json.dumps(sbom, indent=2))
    return str(filepath)


@pytest.fixture
def cyclonedx_xml_with_path(temp_dir):
    """CycloneDX SBOM in XML format with path properties."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>stdlib</name>
      <version>go1.25.6</version>
      <licenses>
        <expression>BSD-3-Clause</expression>
      </licenses>
      <properties>
        <property name="syft:package:type">go-module</property>
        <property name="syft:location:0:path">/usr/bin/service-a</property>
      </properties>
    </component>
    <component type="library">
      <name>stdlib</name>
      <version>go1.25.6</version>
      <licenses>
        <expression>BSD-3-Clause</expression>
      </licenses>
      <properties>
        <property name="syft:package:type">go-module</property>
        <property name="syft:location:0:path">/usr/bin/service-b</property>
      </properties>
    </component>
  </components>
</bom>
"""
    filepath = temp_dir / "with_path.xml"
    filepath.write_text(xml_content)
    return str(filepath)


@pytest.fixture
def cyclonedx_xml_without_path(temp_dir):
    """CycloneDX SBOM in XML format without path properties (typical case)."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<bom xmlns="http://cyclonedx.org/schema/bom/1.4" version="1">
  <components>
    <component type="library">
      <name>example-lib</name>
      <version>1.0.0</version>
      <licenses>
        <expression>MIT</expression>
      </licenses>
    </component>
    <component type="library">
      <name>another-lib</name>
      <version>2.0.0</version>
      <licenses>
        <expression>Apache-2.0</expression>
      </licenses>
    </component>
  </components>
</bom>
"""
    filepath = temp_dir / "no_path.xml"
    filepath.write_text(xml_content)
    return str(filepath)


@pytest.fixture
def spdx_tag_file(temp_dir):
    """SPDX SBOM in TagValue format."""
    tag_content = """SPDXVersion: SPDX-2.3
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: test-sbom

PackageName: example-lib
SPDXID: SPDXRef-Package-example-lib
PackageVersion: 1.0.0
PackageLicenseConcluded: MIT

PackageName: another-lib
SPDXID: SPDXRef-Package-another-lib
PackageVersion: 2.0.0
PackageLicenseConcluded: Apache-2.0
"""
    filepath = temp_dir / "test.spdx"
    filepath.write_text(tag_content)
    return str(filepath)


@pytest.fixture
def spdx_rdf_file(temp_dir):
    """SPDX SBOM in RDF format."""
    rdf_content = """<?xml version="1.0" encoding="UTF-8"?>
<rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"
         xmlns:spdx="http://spdx.org/rdf/terms#">
  <spdx:SpdxDocument rdf:about="http://example.org/sbom">
    <spdx:specVersion>SPDX-2.3</spdx:specVersion>
    <spdx:name>test-sbom</spdx:name>
  </spdx:SpdxDocument>
  <spdx:Package rdf:about="http://example.org/package/example-lib">
    <spdx:name>example-lib</spdx:name>
    <spdx:versionInfo>1.0.0</spdx:versionInfo>
    <spdx:licenseConcluded rdf:resource="http://spdx.org/licenses/MIT"/>
  </spdx:Package>
  <spdx:Package rdf:about="http://example.org/package/another-lib">
    <spdx:name>another-lib</spdx:name>
    <spdx:versionInfo>2.0.0</spdx:versionInfo>
    <spdx:licenseConcluded rdf:resource="http://spdx.org/licenses/Apache-2.0"/>
  </spdx:Package>
</rdf:RDF>
"""
    filepath = temp_dir / "test.spdx.rdf"
    filepath.write_text(rdf_content)
    return str(filepath)


@pytest.fixture
def spdx_xml_file(temp_dir):
    """SPDX SBOM in XML format."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<Document xmlns="http://www.spdx.org/schema/spdx">
  <specVersion>SPDX-2.3</specVersion>
  <name>test-sbom</name>
  <packages>
    <name>example-lib</name>
    <versionInfo>1.0.0</versionInfo>
    <licenseConcluded>MIT</licenseConcluded>
  </packages>
  <packages>
    <name>another-lib</name>
    <versionInfo>2.0.0</versionInfo>
    <licenseConcluded>Apache-2.0</licenseConcluded>
  </packages>
</Document>
"""
    filepath = temp_dir / "test.spdx.xml"
    filepath.write_text(xml_content)
    return str(filepath)
