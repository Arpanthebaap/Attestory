FROM node:20-slim
WORKDIR /app
COPY package.json ./
RUN npm install --omit=dev
COPY backend/ ./backend/
ENV NODE_ENV=production
EXPOSE 8080
CMD ["npm", "start"]
