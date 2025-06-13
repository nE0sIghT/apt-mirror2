ARG PYTHON_VERSION

FROM docker.io/python:$PYTHON_VERSION
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

COPY requirements.txt /tmp/pip-tmp/
COPY requirements/ /tmp/pip-tmp/requirements/

RUN \
    sed -i -e 's#Types: deb#Types: deb deb-src#' /etc/apt/sources.list.d/debian.sources ;\
    apt-get update ;\
    apt-get -y install \
        bash-completion \
        coreutils \
        devscripts \
        git \
        git-gui \
        gitk \
        gpgv \
        sudo \
    ;\
    pip --disable-pip-version-check --no-cache-dir install \
        -r /tmp/pip-tmp/requirements.txt \
        -r /tmp/pip-tmp/requirements/aiofiles.txt \
        -r /tmp/pip-tmp/requirements/dev.txt ;\
    rm -rf /tmp/pip-tmp ;\
    adduser --disabled-password --gecos '' vscode ;\
    echo "vscode ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/vscode

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1

ENTRYPOINT [ "/bin/sh" ]
CMD [ "-c", "sleep infinity" ]
