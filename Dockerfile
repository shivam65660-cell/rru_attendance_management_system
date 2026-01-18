# Use official Python image
FROM python:3.10-slim

# Set working directory inside container
WORKDIR /app

# Copy project files
COPY . /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    libsqlite3-dev \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Ensure uploads folder exists
RUN mkdir -p /app/uploads/notifications

# Expose port Render will use
EXPOSE 10000

# Run Flask app with Gunicorn
CMD ["gunicorn", "-w", "2", "-b", "0.0.0.0:10000", "app:app"]
