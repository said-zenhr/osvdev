# syntax=docker/dockerfile:1
FROM ruby:3.3-alpine AS build

WORKDIR /app

RUN apk add --no-cache build-base

COPY Gemfile Gemfile.lock ./

RUN bundle config set --local without "development test" \
 && bundle install --jobs 4 --retry 3

# --- runtime ---
FROM ruby:3.3-alpine AS runtime

WORKDIR /app

COPY --from=build /usr/local/bundle /usr/local/bundle
COPY . .

RUN chmod +x bin/stackwatch

ENV STACKWATCH_STATE_PATH=/data/state.json
VOLUME ["/data"]

ENTRYPOINT ["bin/stackwatch"]
CMD ["run"]
