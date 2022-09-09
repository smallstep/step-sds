FROM smallstep/step-sds:latest AS sds
FROM envoyproxy/envoy:v1.23.1

RUN apt-get update
RUN apt-get install -y python3
RUN mkdir /src

ADD sds/steppath/sds/sds_client.crt /src
ADD sds/steppath/sds/sds_client_key /src
ADD sds/steppath/sds/root_ca.crt /src
ADD envoy-sds/hot-restarter.py /src
ADD envoy-sds/start-envoy.sh /src
ADD envoy-sds/server.yaml /src
# SDS server
ADD envoy-sds/entrypoint.sh /src
ADD envoy-sds/sds.json /src
COPY --from=sds /usr/local/bin/step /usr/local/bin/step
COPY --from=sds /usr/local/bin/step-sds /usr/local/bin/step-sds

ENTRYPOINT [ "/src/entrypoint.sh" ]
CMD ["python3", "/src/hot-restarter.py", "/src/start-envoy.sh"]
