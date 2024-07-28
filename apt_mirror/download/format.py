# SPDX-License-Identifer: GPL-3.0-or-later


# Fred Cirera
# Sridhar Ratnakumar
# https://stackoverflow.com/a/1094933
def format_size(size: float, suffix: str = "B"):
    for unit in ("", "Ki", "Mi", "Gi"):
        if abs(size) < 1024.0:
            return f"{size:3.1f} {unit}{suffix}"

        size /= 1024.0

    return f"{size:.1f} Ti{suffix}"
