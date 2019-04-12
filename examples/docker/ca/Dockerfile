FROM smallstep/step-ca:latest

USER step
COPY --chown=step:step steppath /home/step

STOPSIGNAL SIGTERM

CMD /usr/local/bin/step-ca --password-file /run/secrets/password /home/step/config/ca.json
