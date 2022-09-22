FROM python:latest

RUN apt update

RUN apt -y install python3-dev python3-pip

COPY requirements.txt /requirements.txt

RUN python3 -m pip install -r /requirements.txt

RUN mkdir /login_system

COPY . /login_system

WORKDIR /login_system

EXPOSE 5000

ENTRYPOINT ["bash", "start_application.sh"]
