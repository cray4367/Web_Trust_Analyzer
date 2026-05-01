# Build stage
FROM node:22-alpine AS builder

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# These ARGs are passed from docker-compose build.args and baked into the Vite bundle.
ARG VITE_API_URL=/api
ARG VITE_TARGET_URL=/
ARG VITE_WAF_API_KEY=""
ENV VITE_API_URL=$VITE_API_URL
ENV VITE_TARGET_URL=$VITE_TARGET_URL
ENV VITE_WAF_API_KEY=$VITE_WAF_API_KEY

RUN npm run build

# Production stage - use Node.js to serve static files instead of nginx
FROM node:22-alpine

WORKDIR /app

# Install serve package to serve static files
RUN npm install -g serve

COPY --from=builder /app/dist /app/dist

EXPOSE 3001

CMD ["serve", "-s", "/app/dist", "-l", "3001"]
