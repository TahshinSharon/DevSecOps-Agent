# Use Node 20 LTS instead of Node 22 to avoid npm 10/12 install instability in Docker builds.
FROM node:20-alpine AS build
WORKDIR /app

# Copy only package.json so Docker cache works and we avoid stale lock files.
COPY package.json ./

# Use npm install instead of npm ci because the previous generated lock file contained
# environment-specific resolved package URLs and npm was failing with "Exit handler never called".
RUN npm config set registry https://registry.npmjs.org/ \
    && npm install --no-audit --no-fund --legacy-peer-deps

COPY . .

# Empty API base makes the browser call /api and /ws on the same host.
ARG VITE_API_BASE=
ENV VITE_API_BASE=${VITE_API_BASE}
RUN npm run build

FROM nginx:1.27-alpine
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build /app/dist /usr/share/nginx/html
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
