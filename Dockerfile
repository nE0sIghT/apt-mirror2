ARG PYTHON_VERSION
ARG BASE_IMAGE

FROM docker.io/python:$PYTHON_VERSION as builder
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

COPY ./ /tmp/apt-mirror2/

RUN \
    pushd /tmp/apt-mirror2 ;\
    pip --disable-pip-version-check --no-cache-dir install \
        -r requirements.txt \
        -r requirements/dev.txt ;\
    pip install . ;\
    popd ;\
    rm -rf /tmp/apt-mirror2 ;\
    pyinstaller \
        --clean \
        --onefile \
        --noconfirm \
        --name apt-mirror \
        /usr/local/bin/apt-mirror

FROM $BASE_IMAGE
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

COPY --from=builder /dist/apt-mirror /usr/local/bin/apt-mirror

ENTRYPOINT [ "apt-mirror" ]
CMD [ ]
