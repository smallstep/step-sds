FROM smallstep/step-sds:latest AS sds
FROM buoyantio/emojivoto-web:v8 AS web
FROM buoyantio/emojivoto-emoji-svc:v8 AS emoji
FROM buoyantio/emojivoto-voting-svc:v8 AS voting
FROM envoyproxy/envoy-alpine:v1.10.0

# Add entrypoint
ADD entrypoint.sh       /usr/local/bin

# ADD envoy-sds/sds.json /src
COPY --from=sds /usr/local/bin/step /usr/local/bin/step
COPY --from=sds /usr/local/bin/step-sds /usr/local/bin/step-sds

# Add emojivoto
COPY --from=web /usr/local/bin/emojivoto-web /usr/local/bin/emojivoto-web
COPY --from=web /usr/local/bin/emojivoto-vote-bot /usr/local/bin/emojivoto-vote-bot
COPY --from=web /usr/local/bin/dist /usr/local/bin/dist
COPY --from=web /usr/local/bin/web /usr/local/bin/web
COPY --from=emoji /usr/local/bin/emojivoto-emoji-svc /usr/local/bin/emojivoto-emoji-svc
COPY --from=voting /usr/local/bin/emojivoto-voting-svc /usr/local/bin/emojivoto-voting-svc

ENV SERVICE_CLUSTER     emojivoto
ENV SERVICE_NODE        envoy

ENTRYPOINT [ "entrypoint.sh" ]
CMD ["emojivoto-web"]
