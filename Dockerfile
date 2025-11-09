# This tells Docker to use 'alpine', a tiny, minimal Linux image
# It's only 5MB, so it's extremely fast to download
FROM alpine:latest

# Set the "working directory" inside the container
WORKDIR /sandbox

# Install 'procps', a tool that lets us see running processes
RUN apk add --no-cache procps

# When the container starts, run a command that does nothing
# but keeps the container alive so we can connect to it.
CMD ["tail", "-f", "/dev/null"]