ARG PYTHON_VERSION

FROM docker.io/python:$PYTHON_VERSION
SHELL ["/bin/bash", "-exo", "pipefail", "-c"]

COPY ./ /tmp/apt-mirror2/

RUN \
    pushd /tmp/apt-mirror2 ;\
    pip --disable-pip-version-check --no-cache-dir install \
        -r requirements.txt ;\
    pip install . ;\
    popd ;\
    rm -rf /tmp/apt-mirror2

ENTRYPOINT [ "apt-mirror" ]
CMD [ ]
