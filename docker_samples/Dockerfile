FROM python:3.10

USER root

RUN apt-get update && apt-get install -y cron
RUN apt-get install -y vim

WORKDIR /opt/sophos-siem

run mkdir /opt/docker/

RUN echo '0,10,20,30,40,50 * * * *   cd /opt/sophos-siem && /usr/local/bin/python siem.py ' >/etc/cron.d/sophos-siem-cron
RUN crontab /etc/cron.d/sophos-siem-cron
RUN cron
RUN touch /var/log/cron.log
RUN echo 'cron -L 2 && tail -f /var/log/cron.log' >/opt/docker/entrypoint.sh

ENTRYPOINT ["/bin/bash", "/opt/docker/entrypoint.sh"]
