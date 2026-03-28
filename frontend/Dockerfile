# NIDS Frontend Dockerfile (React + nginx)
FROM node:20-alpine AS builder

WORKDIR /app
COPY frontend/package.json frontend/package-lock.json* ./
RUN npm ci

COPY frontend/ ./
RUN npm run build

FROM nginx:alpine

# Copy built React app
COPY --from=builder /app/dist /usr/share/nginx/html

# Nginx config for SPA routing with API and WebSocket proxy
RUN echo 'server { \
    listen 80; \
    server_name _; \
    root /usr/share/nginx/html; \
    index index.html; \
    \
    # SPA routing \
    location / { \
        try_files $uri $uri/ /index.html; \
    } \
    \
    # API proxy \
    location /api/ { \
        proxy_pass http://nids:8000/api/; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for; \
        proxy_set_header X-Forwarded-Proto $scheme; \
    } \
    \
    # WebSocket proxy \
    location /ws/ { \
        proxy_pass http://nids:8000/ws/; \
        proxy_http_version 1.1; \
        proxy_set_header Upgrade $http_upgrade; \
        proxy_set_header Connection "upgrade"; \
        proxy_set_header Host $host; \
        proxy_set_header X-Real-IP $remote_addr; \
        proxy_read_timeout 86400; \
    } \
}' > /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
