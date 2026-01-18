FROM docker:27-cli AS dockercli

FROM node:20-bookworm

WORKDIR /app

# Build deps for node-pty
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 make g++ \
  && rm -rf /var/lib/apt/lists/*

# Docker CLI (static) from docker image
COPY --from=dockercli /usr/local/bin/docker /usr/local/bin/docker

COPY package.json ./
RUN npm install --omit=dev

COPY . .

ENV PORT=8090
EXPOSE 8090

CMD ["npm","start"]
