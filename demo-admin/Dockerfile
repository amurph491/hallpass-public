FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# Production (`--target production`): static files only, served by unprivileged
# nginx on port 8080. The ingress routes /api/ to the Hallpass management API.
FROM nginxinc/nginx-unprivileged:1.27-alpine AS production

COPY nginx.production.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 8080

# Local Compose demo (the default target): proxies /api/ to the demo server.
FROM nginx:1.27-alpine AS demo

COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html

EXPOSE 80
