FROM python:3.9-slim

# Instalează dependențele de sistem pentru iptables
RUN apt-get update && apt-get install -y iptables && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Pornește motorul de inferență
CMD ["python", "real_time_inference.py"]