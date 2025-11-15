# Dockerfile enabling Playwright (Chromium) for the Vanguard API service
# Tailored to this repository structure.
# Base image includes Playwright runtimes and system dependencies.
FROM playwright/python:v1.56.0

# Prevent interactive apt dialogs
ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && playwright install --with-deps

EXPOSE 10000

# Use env PORT if provided, default to 10000
CMD ["bash", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-10000}"]
