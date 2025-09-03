FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .

RUN pip install --upgrade pip setuptools wheel
RUN pip install torch==2.8.0 torchaudio==2.8.0 -f https://download.pytorch.org/whl/cpu/torch_stable.html
RUN pip install -r requirements.txt --use-pep517

COPY . .

ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0

EXPOSE 5000

CMD ["gunicorn", "-b", "0.0.0.0:5000", "app:app"]
