FROM python:3.12-slim

WORKDIR /srv

# Install Python dependencies first (layer cache)
COPY app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source into /srv
COPY app/ .

# Non-root user for security
RUN adduser --disabled-password --gecos '' clipuser
USER clipuser

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
