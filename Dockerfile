# Official Playwright image with Python + all browsers preinstalled
FROM playwright/python:v1.56.0

# Avoid interactive prompts
ENV DEBIAN_FRONTEND=noninteractive

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt \
    && playwright install --with-deps

# Expose port (Render uses PORT env)
EXPOSE 10000

# Start the API server
CMD ["bash", "-c", "uvicorn api_server:app --host 0.0.0.0 --port ${PORT:-10000}"]
