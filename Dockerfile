FROM cgr.dev/chainguard/python:latest-dev AS builder
ARG VERSION=0.5.6

ENV LANG=C.UTF-8
ENV PATH="/app/venv/bin:$PATH"

WORKDIR /app

RUN python -m venv /app/venv

RUN pip install sbomdiff==${VERSION}

FROM cgr.dev/chainguard/python:latest

WORKDIR /app

ENV PATH="/venv/bin:$PATH"

COPY --from=builder /app/venv /venv

ENTRYPOINT [ "python", "/venv/bin/sbomdiff" ]