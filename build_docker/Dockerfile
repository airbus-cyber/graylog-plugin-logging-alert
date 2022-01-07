# Build:
# docker build --tag graylog.plugin.build:latest .
# Execute:
# docker run --interactive --tty --rm --user $(id --user):$(id --group) --mount type=bind,source=$(pwd),target=/host graylog.plugin.build:latest

FROM ubuntu:20.04

RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install --assume-yes openjdk-8-jdk-headless openjdk-8-jre-headless maven git gnupg2 rpm expect nodejs

ENV HOME=/host
ENV MAVEN_OPTS="-Duser.home=/host"

WORKDIR /host
