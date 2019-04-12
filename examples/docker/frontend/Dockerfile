FROM python:3-alpine

RUN mkdir /src

ADD server.py /src
ADD requirements.txt /src
RUN pip3 install -r /src/requirements.txt

CMD ["python3", "/src/server.py"]
