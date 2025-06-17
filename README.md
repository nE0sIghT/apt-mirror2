# apt-mirror2

[`apt-mirror2`](https://gitlab.com/apt-mirror2/apt-mirror2) is the Python/asyncio reimplementation of the
[apt-mirror](https://github.com/apt-mirror/apt-mirror) - an apt sources mirroring
tool.  
This project is intended to be a general drop-in [apt-mirror](https://github.com/apt-mirror/apt-mirror) replacement.  

One of the main advantages of the `apt-mirror2` over the `apt-mirror` is that it never leaves a broken mirror behind, provided it exits with code 0.
This is ensured by data integrity checks at all stages of mirroring.

# Requirements

Python 3.10 is the minimum supported version. PyPy 3.10 (7.3) is also supported.  
For additional dependencies, please refer to the `pyproject.toml` and/or `requirements.txt`.

# Installation
## Container (Docker/Podman)

Container images are available in the Docker Hub under [aptmirror/apt-mirror2](https://hub.docker.com/r/aptmirror/apt-mirror2) repository and in the
Red Hat Quay.io under [apt-mirror2/apt-mirror2](https://quay.io/repository/apt-mirror2/apt-mirror2) repository.

Supported architectures: amd64, arm64v8.

You can try them using

```bash
docker run -it --rm docker.io/aptmirror/apt-mirror2 --help
```

or

```bash
docker run -it --rm quay.io/apt-mirror2/apt-mirror2 --help
```

You may wish to use `podman` command instead of `docker`.

### Image variants
#### `aptmirror/apt-mirror2:latest`
#### `aptmirror/apt-mirror2:<version>`

Images based on `debian:stable` image.

#### `aptmirror/apt-mirror2:slim`
#### `aptmirror/apt-mirror2:<version>-slim`

Images based on `debian:stable-slim` image.

#### `aptmirror/apt-mirror2:alpine`
#### `aptmirror/apt-mirror2:<version>-alpine`

Images based on `alpine:3` image.

## PyPI

PyPI package is available under the name [`apt-mirror`](https://pypi.org/project/apt-mirror/):

```bash
pip install apt-mirror
apt-mirror --help
```

## Distro packages

[![Packaging status](https://repology.org/badge/vertical-allrepos/apt-mirror2.svg)](https://repology.org/project/apt-mirror2/versions)

### Debian

`apt-mirror2` is available in the Debian Unstable (sid). Please note that as of now, `apt-mirror2` does not
replace `apt-mirror` in the Debian and thus package provides `apt-mirror2` executable and
`/etc/apt/mirror2.list` configuration file.

### Packagecloud builds

Debian (bookworm, trixie) and Ubuntu (22.04, 24.04) packages are available in the [Packagecloud repository](https://packagecloud.io/nE0sIghT/apt-mirror2).

Quick automated repository setup:

```sh
curl -s https://packagecloud.io/install/repositories/nE0sIghT/apt-mirror2/script.deb.sh | sudo bash
```

Package installation:

```sh
sudo apt-get install apt-mirror2
```

For manual steps, please refer to the [Packagecloud repository](https://packagecloud.io/nE0sIghT/apt-mirror2).

## Build from source with virtualenv

It's possible to use `apt-mirror2` from a virtualenv:

```bash
# Let's work in the home folder
cd

# Create virtualenv
virtualenv ~/venv/apt-mirror2
source ~/venv/apt-mirror2/bin/activate

# Clone apt-mirror2 source code
git clone https://gitlab.com/apt-mirror2/apt-mirror2
cd apt-mirror2

# Install requirements
pip install -r requirements.txt

# Install apt-mirror2 into virtualenv
python setup.py install

apt-mirror --help
```

# Usage

As the drop-in replacement for the `apt-mirror`, this project supports same CLI syntax.

```
usage: apt-mirror [-h] [--version] [configfile]

positional arguments:
  configfile  Path to config file. Default /etc/apt/mirror.list

options:
  -h, --help  show this help message and exit
  --version   Show version
```

# apt-mirror compatibility

Most of `apt-mirror` configuration directives are supported.  
As of now proxy for FTP repositories is not supported.  

File lists (ALL, NEW, MD5, SHA256, SHA512) are not written by default, but you can enable them with the `write_file_lists` option.

In addition there are some enhancements available:

- Non-zero exit code is returned if some of required files were not downloaded due to network or server errors or
  no repositories were configured.
- Flexible support for filtering by package name, source name, section, or Debtags
- Optional Release files GPG signature verification
- Repositories lacking MD5 hashes are correctly mirrored
- Old index files are properly cleaned and don't produce errors during the mirror processing
- Standard sources.list `[ arch=arch1,arch2 ]` can be used to specify multiple repository architectures for mirroring.
- Multiple codenames (or flat folders) can be specified using comma as delimiter.
- `mirror_path URL PATH` option may be used to specify `PATH` to use for saving mirror files instead of the path that is generated from `URL`.
- Additional configurations are loaded from the `*.list` files in the directory named the same as the `configfile` with the `.d` suffix. Eg `/etc/apt/mirror.list.d/*.list`.
- Rate limit is enforced for overall download rate.
- Slow download rate protection is enabled by default and can be configured via `mirror.list`.
- HTTP user agent can be configured via `user_agent` configuration.
- Configuration variables are exposed to the postmirror_script.
- `by-hash` list option can be used to control whether `Acquire-By-Hash` Release option should be respected or enforced.
- Mirror wipe protection is available and configurable via `wipe_size_ratio` and `wipe_count_ratio` settings.
- Per-repository log files are available in the `var_path` folder
- The `dists` folder is replaced almost atomically using move instead of copy/link
- Native Prometheus metrics are supported

# Common problems
## `LocalProtocolError: Max outbound streams is n, n open`

This warning may appear with HTTP2 mirrors when you have too much `nthreads` configured. You may either
lower `nthreads` value or disable http2 via `http2-disable` option. As of now, apt-mirror2 has no control over HTTP2 concurrent streams value used by
httpx/h2 client, but does limit the count of simultaneously downloaded files (which can still exceed maximum outbound streams due to unknown reasons).

## `RuntimeError: can't start new thread`

Long story short: upgrade Docker.

Look to [this issue](https://gitlab.com/apt-mirror2/apt-mirror2/-/issues/33#note_2377422047) for more solutions.

## `dists` folder is missing after running apt-mirror2

This is usually a result of errors in your source mirror. You should see some warnings either about missing files in the source or problems with metadata files.
There should be a `Metadata movement skipped because of download errors` message in the log file and apt-mirror2 should exit with non-zero code.

You could try to change your mirror source, report this problem to the mirror owner, or increase the timeouts in your mirror.list.

# License

GNU General Public License v3.0 or later
