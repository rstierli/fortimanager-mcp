FROM python:3.12-slim

WORKDIR /app

# Install uv for faster package installation
RUN pip install uv

# Copy project files
COPY pyproject.toml .
COPY src/ src/

# Install dependencies
RUN uv pip install --system .

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO

# Run the server
CMD ["fortimanager-mcp"]
