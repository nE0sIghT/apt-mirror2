# SPDX-License-Identifer: GPL-3.0-or-later


class PackageFilter:
    def __init__(self) -> None:
        self.include_source_name: set[str] = set()
        self.exclude_source_name: set[str] = set()
        self.include_binary_packages: set[str] = set()
        self.exclude_binary_packages: set[str] = set()

    def package_allowed(
        self, source_name: str, package_name: str | None = None
    ) -> bool:
        if self.include_source_name and source_name not in self.include_source_name:
            return False

        if self.exclude_source_name and source_name in self.exclude_source_name:
            return False

        if package_name:
            if (
                self.include_binary_packages
                and package_name not in self.include_binary_packages
            ):
                return False

            if (
                self.exclude_binary_packages
                and package_name in self.exclude_binary_packages
            ):
                return False

        return True
