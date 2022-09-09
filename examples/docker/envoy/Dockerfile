FROM envoyproxy/envoy:v1.23-latest

RUN apt-get update
RUN apt-get install -y python3

RUN mkdir /src
ADD sds/steppath/sds/sds_client.crt /src
ADD sds/steppath/sds/sds_client_key /src
ADD sds/steppath/sds/root_ca.crt /src
ADD envoy/hot-restarter.py /src
ADD envoy/start-envoy.sh /src
ADD envoy/server.yaml /src

CMD ["python3", "/src/hot-restarter.py", "/src/start-envoy.sh"]
