FROM golang:1.24-alpine AS build
ARG COVER=false
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build $([ "$COVER" = "true" ] && echo "-cover") -o /oidc-mock .

FROM alpine:3.21 AS dev
COPY --from=build /oidc-mock /oidc-mock
ENTRYPOINT ["/oidc-mock"]

FROM scratch
COPY --from=build /oidc-mock /oidc-mock
ENTRYPOINT ["/oidc-mock"]
