# Run the web service on container startup. Here we use the gunicorn
# webserver, with one worker process and 8 threads.
# For environments with multiple CPU cores, increase the number of workers
# to be equal to the cores available.
# Timeout is set to 0 to disable the timeouts of the workers to allow Cloud Run to handle instance scaling.
# CMD exec gunicorn --bind :$PORT --workers 1 --threads 8 --timeout 0 main:app
FROM python:3.11-bookworm as builder

RUN pip install poetry==1.5.1

ENV POETRY_NO_INTERACTION=1 \
    POETRY_VIRTUALENVS_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=1 \
    POETRY_CACHE_DIR=/tmp/poetry_cache

WORKDIR /app

COPY pyproject.toml poetry.lock ./

RUN touch README.md

RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --without dev --no-root

FROM python:3.11-slim-bookworm as runtime

ENV VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

COPY moe_gthr_auth_server ./moe_gthr_auth_server

COPY entrypoint.sh gunicorn.conf.py ./

EXPOSE 8080

ENTRYPOINT ["/bin/sh","./entrypoint.sh"]

# base example dockerfile
#
# FROM python:3.11-buster as builder

# RUN pip install poetry==1.4.2

# ENV POETRY_NO_INTERACTION=1 \
#     POETRY_VIRTUALENVS_IN_PROJECT=1 \
#     POETRY_VIRTUALENVS_CREATE=1 \
#     POETRY_CACHE_DIR=/tmp/poetry_cache

# WORKDIR /app

# COPY pyproject.toml poetry.lock ./
# RUN touch README.md

# RUN --mount=type=cache,target=$POETRY_CACHE_DIR poetry install --without dev --no-root

# FROM python:3.11-slim-buster as runtime

# ENV VIRTUAL_ENV=/app/.venv \
#     PATH="/app/.venv/bin:$PATH"

# COPY --from=builder ${VIRTUAL_ENV} ${VIRTUAL_ENV}

# COPY annapurna ./annapurna

# ENTRYPOINT ["python", "-m", "annapurna.main"]
