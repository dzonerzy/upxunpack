FROM python:3.11.0-slim-bullseye
RUN mkdir /app
WORKDIR /app
COPY requirements.txt /app/requirements.txt
COPY unpack.py /app/unpack.py
COPY example.tar.gz /app/example.tar.gz
COPY rootfs.tar.gz /app/rootfs.tar.gz
RUN tar -xvf rootfs.tar.gz
RUN tar -xvf example.tar.gz
RUN pip install -r requirements.txt
RUN python unpack.py -h