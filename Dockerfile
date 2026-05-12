FROM python:3.13-slim

WORKDIR /app

# Install system deps required by sentence-transformers / chromadb
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        git \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pre-create runtime directories
RUN mkdir -p data/chroma reports benchmarks/runs

EXPOSE 8000

# Allow Ollama URL override for Docker networking
ENV OLLAMA_URL=http://ollama:11434

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
