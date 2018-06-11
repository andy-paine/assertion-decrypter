FROM gradle:4.7.0-jdk8 as build

WORKDIR /assertion-decrypter
USER root
ENV GRADLE_USER_HOME ~/.gradle

COPY build.gradle build.gradle
RUN gradle install

COPY src/ src/

RUN gradle installDist

FROM openjdk:8-jre

WORKDIR /stub-idp

COPY --from=build /assertion-decrypter/build/install/assertion-decrypter .

ENTRYPOINT ["bin/assertion-decrypter"]
