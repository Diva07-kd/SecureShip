# Stage 1: Build React Application
FROM node:22-alpine AS builder
WORKDIR /app

# Copy package descriptors and install dependencies
COPY package.json package-lock.json* ./
RUN npm install

# Copy source and build static distribution
COPY . ./
RUN npm run build

# Stage 2: Hardened Alpine Nginx Web Server
FROM nginx:alpine AS runner

# Remove default nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy built distribution from builder
COPY --from=builder /app/dist /usr/share/nginx/html

# Copy optimized nginx reverse proxy configuration
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Healthcheck
HEALTHCHECK --interval=10s --timeout=3s --retries=3 \
  CMD wget --spider -q http://127.0.0.1:80/healthz || exit 1

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]
