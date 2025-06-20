# Use official Python image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy files
COPY recon_tool.py /app/recon_tool.py
COPY README.md /app/README.md

# Install dependencies
RUN pip install whois dnspython requests

# Set default command
ENTRYPOINT ["python", "recon_tool.py"]
