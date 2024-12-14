FROM node:18-bullseye

WORKDIR /app

# Copiar archivos de la aplicación
COPY server/package*.json ./
RUN npm install

COPY server .

EXPOSE 3000

CMD ["node", "server.js"]