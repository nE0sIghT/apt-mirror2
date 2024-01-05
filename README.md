# About

`apt-mirror2` is the Python/asyncio reimplementation of the [apt-mirror](https://github.com/apt-mirror/apt-mirror) developed as drop-in replacement for the latest.  
This project is in early development stage however it should be suitable as general [apt-mirror](https://github.com/apt-mirror/apt-mirror) replacement.

# Requirements

Python 3.10 is the minimum supported version.  
For additional dependencies look to the `pyproject.yml` and/or `requirements.txt`.

# Installation
As for now the most easy way to try this project is to use virtualenv:

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
usage: apt-mirror [-h] [configfile]

positional arguments:
  configfile  Path to config file. Default /etc/apt-mirror/mirror.list

options:
  -h, --help  show this help message and exit
```

# apt-mirror configuration compatibility

Most of `apt-mirror` configuration directives are supported and the others will be supported.

As of now next options are not supported and ignored:

- `postmirror_script` and `run_postmirror`
- `limit_rate`
- `unlink` - apt-mirror2 always unlink files before saving
- `*proxy*`

In additions there are some enhancements supported:

- Standard source.list `[ arch=arch1,arch2 ]` options are supported to specify multiple repository architectures for mirroring.
- `mirror_path URL PATH` option may be used to specify `PATH` to use for saving mirror files instead of path that is generated from `URL`.

# License

GNU General Public License v3.0 or later
