# apt-mirror2

[`apt-mirror2`](https://gitlab.com/apt-mirror2/apt-mirror2) is the Python/asyncio reimplementation of the
[apt-mirror](https://github.com/apt-mirror/apt-mirror) developed as drop-in replacement for the latest.  
This project should be suitable as general [apt-mirror](https://github.com/apt-mirror/apt-mirror) replacement.  

One of the main advantages of the `apt-mirror2` over the `apt-mirror` - you should never got broken mirror in case `apt-mirror2` returns 0 exit code.
This is ensured by data integrity checks at all stages of mirroring.

# Requirements

Python 3.10 is the minimum supported version.  
For additional dependencies look to the `pyproject.yml` and/or `requirements.txt`.

# Installation
## Docker

Docker image is available in the Docker Hub under [aptmirror/apt-mirror2](https://hub.docker.com/r/aptmirror/apt-mirror2) repository.
You can try it using

```bash
docker run -it --rm aptmirror/apt-mirror2 --help
```

## PyPi

PyPi package is available with the name [`apt-mirror`](https://pypi.org/project/apt-mirror/):

```bash
pip install apt-mirror
apt-mirror --help
```

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

As the drop-in replacement for the `apt-mirror` this project supports same CLI syntax.

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

- Repositories without MD5 hashsums are correctly mirrored
- Old index files are properly cleaned and don't produces errors in mirror processing
- Standard source.list `[ arch=arch1,arch2 ]` can be used to specify multiple repository architectures for mirroring.
- multiple codenames (or flat folders) can be specified using comma as delimiter.
- `mirror_path URL PATH` option may be used to specify `PATH` to use for saving mirror files instead of path that is generated from `URL`.
- Additional configuration is loaded from the `*.list` files in the directory named same as `configfile` with the `.d` suffix. Eg `/etc/apt/mirror.list.d/*.list`.
- Rate limit is enforced for overall download rate.
- Non-zero exit code is returned if some of required files were not downloaded due to network or server errors or
  no repositories were configured.
- HTTP user agent can be configured via `user_agent` configuration.
- Configuration variables are exposed to postmirror_script.
- `by-hash` list option can be used to control whether `Acquire-By-Hash` Release option should be respected or enforced.
- mirror wipe protection is available and configurable via `wipe_size_ratio` and `wipe_count_ratio` settings.
- per-repository log files are available in the `var_path` folder
- `dists` folder is almost atomicaly replaced using move instead of copy/link
- native Prometheus metrics are supported

# License

GNU General Public License v3.0 or later
