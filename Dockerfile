# Alternative to render.yaml's native Python runtime.
# Render: set runtime: docker (or use this with any container host).
FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    OBF_TIMEOUT=60 \
    OBF_MAX_SOURCE=262144 \
    OBF_MAX_BODY=16777216

WORKDIR /app
COPY . .

# Official Luau toolchain (luau-ast / luau-compile / luau / luau-analyze).
RUN python3 obf/fetch_tools.py

EXPOSE 10000
CMD ["python3", "-m", "obf.web"]
