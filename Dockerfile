ARG PYTHON_VERSION
ARG BASE_IMAGE

FROM docker.io/python:$PYTHON_VERSION as builder
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

RUN apt-mirror --version

ENTRYPOINT [ "apt-mirror" ]
CMD [ ]
