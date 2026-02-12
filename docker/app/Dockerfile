FROM python:3.12-slim

WORKDIR /app

COPY vulnerable_app/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY vulnerable_app/ .

RUN groupadd -r appuser && useradd -r -g appuser appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]
