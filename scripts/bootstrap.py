#!/usr/bin/env python
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: Apache-2.0
#
# FastFileLink CLI - Fast, no-fuss file sharing
# Copyright (C) 2025-2026 FastFileLink contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from hashlib import sha256
from pathlib import Path

import tarfile
import urllib.request


class DependencyBootstrapper:
    VERSION = "3.8.13"
    ARCHIVE_NAME = f"gnutls-{VERSION}.tar.xz"
    SOURCE_URL = f"https://www.gnupg.org/ftp/gcrypt/gnutls/v3.8/{ARCHIVE_NAME}"
    SHA256 = "ffed8ec1bf09c2426d4f14aae377de4753b53e537d685e604e99a8b16ca9c97e"

    def __init__(self):
        self.projectRoot = Path(__file__).resolve().parents[1]
        self.thirdPartyDirectory = self.projectRoot / "third_party"
        self.archivePath = self.thirdPartyDirectory / self.ARCHIVE_NAME
        self.sourceDirectory = self.thirdPartyDirectory / f"gnutls-{self.VERSION}"

    def _verifyArchive(self):
        digest = sha256(self.archivePath.read_bytes()).hexdigest()
        if digest != self.SHA256:
            raise RuntimeError(f"GnuTLS archive SHA256 mismatch: {digest}")

    def bootstrap(self):
        self.thirdPartyDirectory.mkdir(parents=True, exist_ok=True)
        if self.sourceDirectory.exists():
            return

        if not self.archivePath.exists():
            urllib.request.urlretrieve(self.SOURCE_URL, self.archivePath)
        self._verifyArchive()

        with tarfile.open(self.archivePath, "r:xz") as archive:
            destination = self.thirdPartyDirectory.resolve()
            for member in archive.getmembers():
                memberPath = (destination / member.name).resolve()
                if destination not in memberPath.parents and memberPath != destination:
                    raise RuntimeError(f"Unsafe archive member: {member.name}")
            archive.extractall(self.thirdPartyDirectory)


def main():
    DependencyBootstrapper().bootstrap()


if __name__ == "__main__":
    main()
