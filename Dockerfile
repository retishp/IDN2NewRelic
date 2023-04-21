FROM python:3-buster
RUN pip install requests azure-appconfiguration
#RUN apt-get update && apt-get install -y syslog-ng-core
WORKDIR /app
ADD IDN2NewRelic.py /app/
#CMD [ "python", "/app/IDN2NewRelic.py" ]