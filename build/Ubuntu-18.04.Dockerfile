FROM ruby:2.6.3-stretch

RUN apt-get update && apt-get install curl git -y

RUN mkdir binary
RUN curl -sSL https://get.haskellstack.org/ | sh
RUN git clone https://github.com/CollegeVine/confcrypt

RUN cd confcrypt && stack install
VOLUME binary

RUN cp -r "$(stack path --local-bin)/" binary/
