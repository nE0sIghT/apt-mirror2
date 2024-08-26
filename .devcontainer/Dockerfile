ARG DEBIAN_VERSION

FROM docker.io/debian:$DEBIAN_VERSION
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

RUN \
    sed -i -e 's#Types: deb#Types: deb deb-src#' /etc/apt/sources.list.d/debian.sources ;\
    echo "C.UTF-8 UTF-8" > /etc/locale.gen ;\
    echo "en_US.UTF-8 UTF-8" >> /etc/locale.gen ;\
    apt-get update ;\
    DEBIAN_FRONTEND=noninteractive apt-get -y install \
        bash-completion \
        coreutils \
        devscripts \
        git \
        git-buildpackage \
        git-gui \
        git-lfs \
        gitk \
        locales \
        pristine-lfs \
        sudo \
    ;\
    adduser --disabled-password --gecos '' vscode ;\
    echo "vscode ALL=(root) NOPASSWD: ALL" > /etc/sudoers.d/vscode ;\
    mkdir -p /workspace ;\
    chown 'vscode:' /workspace

# [Optional] Uncomment this section to install additional OS packages.
# RUN apt-get update && export DEBIAN_FRONTEND=noninteractive \
#     && apt-get -y install --no-install-recommends <your-package-list-here>

# [Optional] Uncomment this line to install global node packages.
# RUN su vscode -c "source /usr/local/share/nvm/nvm.sh && npm install -g <your-package-here>" 2>&1

ENTRYPOINT [ "/bin/sh" ]
CMD [ "-c", "sleep infinity" ]
