ARG PYTHON_VERSION
ARG BASE_IMAGE

FROM docker.io/python:$PYTHON_VERSION AS builder
SHELL ["/bin/sh", "-ex", "-c"]

COPY ./ /tmp/apt-mirror2/

RUN \
    if which apk > /dev/null; then \
        apk add --no-cache \
            binutils \
            gcc \
            linux-headers \
            musl-dev ;\
    fi ;\
    cd /tmp/apt-mirror2 ;\
    pip --disable-pip-version-check --no-cache-dir install \
        -r requirements.txt \
        -r requirements/dev.txt ;\
    pip install . ;\
    cd / ;\
    rm -rf /tmp/apt-mirror2 ;\
    pyinstaller \
        --clean \
        --onefile \
        --noconfirm \
        --copy-metadata aioftp \
        --name apt-mirror \
        /usr/local/bin/apt-mirror

FROM $BASE_IMAGE
SHELL ["/bin/sh", "-ex", "-c"]

COPY --from=builder /dist/apt-mirror /usr/local/bin/apt-mirror

RUN \
    if which apk > /dev/null; then \
        apk upgrade --no-cache ;\
        apk add --no-cache gpgv ;\
    else \
        apt-get -y update ;\
        apt-get -y dist-upgrade ;\
        apt-get -y install gpgv ;\
        rm -rf /var/lib/apt/lists/* ;\
    fi
RUN apt-mirror --version

ENTRYPOINT [ "apt-mirror" ]
CMD [ ]
