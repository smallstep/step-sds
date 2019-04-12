FROM smallstep/step-sds:latest

USER step
RUN mkdir /home/step/secrets
COPY --chown=step:step steppath /home/step
COPY --chown=step:step entrypoint.sh /home/step

STOPSIGNAL SIGTERM
WORKDIR /home/step
ENTRYPOINT [ "/home/step/entrypoint.sh" ]
CMD /usr/local/bin/step-sds run /home/step/config/sds.json --password-file /run/secrets/password --provisioner-password-file /run/secrets/password
