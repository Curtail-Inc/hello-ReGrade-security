# ABOUTME: Runs the team-chat API under gunicorn. Two containers of this image become
# ABOUTME: instance-a and instance-b — same code, different bcrypt salts at boot.
FROM python:3.12-slim
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app/ ./app/
COPY gunicorn.conf.py .
ENV PORT=8000
EXPOSE 8000
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.wsgi:app"]
