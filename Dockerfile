# Use an explicit Node version so Dokploy/buildpack defaults don't break installs
FROM node:20-bookworm-slim

WORKDIR /app

# Install yarn (Dokploy sometimes uses yarn v1; pin it explicitly)
RUN corepack enable && corepack prepare yarn@1.22.22 --activate

# Copy only lockfiles first for better layer caching
COPY package.json yarn.lock ./

# If any dependency needs native builds, keep build tools available
RUN apt-get update \
  && apt-get install -y --no-install-recommends python3 make g++ ca-certificates \
  && rm -rf /var/lib/apt/lists/*

RUN yarn install --frozen-lockfile

# Copy the rest of the app
COPY . .

ENV NODE_ENV=production
EXPOSE 3000

CMD ["node", "server.js"]
