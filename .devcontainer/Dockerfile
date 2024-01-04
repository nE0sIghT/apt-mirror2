ARG PYTHON_VERSION

FROM docker.io/python:$PYTHON_VERSION
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

COPY requirements.txt /tmp/pip-tmp/

RUN \
    sed -i -e 's#Types: deb#Types: deb deb-src#' /etc/apt/sources.list.d/debian.sources ;\
    apt-get update ;\
    apt-get -y install \
        bash-completion \
        coreutils \
        git \
        git-gui \
        gitk \
        libapt-pkg-dev \
        sudo \
    ;\
    pip --disable-pip-version-check --no-cache-dir install \
        -r /tmp/pip-tmp/requirements.txt ;\
    rm -rf /tmp/pip-tmp ;\
    mkdir -p /tmp/python-apt ;\
    pushd /tmp/python-apt ;\
    apt-get source python-apt ;\
    for dir in $(ls -1); do \
        if test -d "${dir}"; then \
            pushd "${dir}" ;\
            python setup.py install ;\
            popd ;\
            break ;\
        fi ;\
    done ;\
    popd ;\
    rm -r /tmp/python-apt ;\
    { python -c 'import apt_pkg' || (echo "python-apt was not installed"; exit 1;) } ;\
    adduser --disabled-password --gecos '' vscode ;\
    echo "vscode ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/vscode

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1

ENTRYPOINT [ "/bin/sh" ]
CMD [ "-c", "sleep infinity" ]
