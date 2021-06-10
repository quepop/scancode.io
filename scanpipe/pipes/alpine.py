# SPDX-License-Identifier: Apache-2.0
#
# http://nexb.com and https://github.com/nexB/scancode.io
# The ScanCode.io software is licensed under the Apache License version 2.0.
# Data generated with ScanCode.io is provided as-is without warranties.
# ScanCode is a trademark of nexB Inc.
#
# You may not use this software except in compliance with the License.
# You may obtain a copy of the License at: http://apache.org/licenses/LICENSE-2.0
# Unless required by applicable law or agreed to in writing, software distributed
# under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.
#
# Data Generated with ScanCode.io is provided on an "AS IS" BASIS, WITHOUT WARRANTIES
# OR CONDITIONS OF ANY KIND, either express or implied. No content created from
# ScanCode.io should be considered or used as legal advice. Consult an Attorney
# for any legal advice.
#
# ScanCode.io is a free software code scanning tool from nexB Inc. and others.
# Visit https://github.com/nexB/scancode.io for support and download.

import json
import os
import posixpath
import re
import subprocess

from packagedcode import alpine
from packageurl import PackageURL

from scanpipe.pipes import scancode

APORTS_URL = "https://gitlab.alpinelinux.org/alpine/aports.git"
APORTS_DIR_NAME = "aports"
APORTS_SUBDIRS = ["main", "non-free", "community", "testing", "unmaintained"]


def extract_source_urls_apkbuild(apkbuild_path):
    """
    Extract all the urls from the APKBUILD's source variable.
    """
    extraction_result = subprocess.run(
        f"source {apkbuild_path} ; echo $source",
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        shell=True,
        check=True,
        executable="/bin/bash",
    )
    return re.findall(
        r"(?:http|https|ftp):\/\/[^\s\"]*", extraction_result.stdout.decode("utf-8")
    )


def extract_copyrights_json(scan_result_path):
    """
    Having scancode result file extract all the copyrights into an array (deduplicated).
    """
    if not os.path.exists(scan_result_path):
        return None
    with open(scan_result_path) as scan_result:
        json_obj = json.load(scan_result)
        copyrights = set()
        for file_obj in json_obj["files"]:
            for copyright in file_obj["copyrights"]:
                copyrights.add(copyright["value"])
        return list(copyrights)


def download_aports_repo(alpine_version, aports_dir):
    """
    Download aports repository.
    """
    ver = alpine_version.split(".")
    if not os.path.exists(aports_dir):
        subprocess.check_call(
            ["git", "clone", "-b", f"{ver[0]}.{ver[1]}-stable", APORTS_URL, aports_dir]
        )


def complement_missing_copyrights(package, aports_dir, out_dir, tmp_dir):
    """
    Check if package is not a subpackage - if not, proceed with copyright extraction.
    Find package's aports subdir - it's APKBUILD path.
    Download all the source code used to build the package.
    Extract it and run scancode over extracted and associated files (aports).
    Complement package's missing copyrights.
    """
    if (
        not package.source_packages
        or package.name == PackageURL.from_string(package.source_packages[0]).name
    ):
        package_id = f"{package.name}_{package.version}"
        package_dir = posixpath.join(tmp_dir, package_id)
        aports_commit_id = package.vcs_url.split("id=")[1]
        scan_result_path = posixpath.join(out_dir, f"{package_id}.json")
        if not os.path.exists(scan_result_path):
            if subprocess.call(["git", "-C", aports_dir, "checkout", aports_commit_id]):
                return
            for repo_branch in APORTS_SUBDIRS:
                apkbuild_dir = posixpath.join(aports_dir, repo_branch, package.name)
                apkbuild_path = posixpath.join(apkbuild_dir, "APKBUILD")
                if not os.path.exists(apkbuild_path):
                    continue
                subprocess.check_call(["cp", "-R", apkbuild_dir, package_dir])
                for url in extract_source_urls_apkbuild(apkbuild_path):
                    subprocess.check_call(["wget", "-P", package_dir, url])
                    scancode.run_extractcode(
                        location=package_dir, options=["--shallow"], raise_on_error=True
                    )
                    scancode.run_scancode(
                        location=package_dir,
                        output_file=scan_result_path,
                        options=["--copyright"],
                        raise_on_error=True,
                    )
                break
        package.copyright = extract_copyrights_json(scan_result_path)


def package_getter(root_dir, **kwargs):
    """
    Download aports repository.
    Yield installed package objects.
    Complement missing copyrights.
    """
    tmp_dir = kwargs["project"].tmp_path
    out_dir = kwargs["project"].output_path
    aports_dir = posixpath.join(tmp_dir, APORTS_DIR_NAME)
    alpine_version = kwargs["version"]

    download_aports_repo(alpine_version, aports_dir)
    packages = alpine.get_installed_packages(root_dir)
    for package in packages:
        complement_missing_copyrights(package, aports_dir, out_dir, tmp_dir)
        yield package.purl, package
