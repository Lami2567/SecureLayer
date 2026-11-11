FROM node:22-alpine AS build
WORKDIR /workspace
COPY package*.json ./
COPY sdk-node/package*.json ./sdk-node/
COPY demo-node-app/package*.json ./demo-node-app/
COPY sdk-node/ ./sdk-node/
COPY demo-node-app/ ./demo-node-app/

RUN npm install
RUN npm --workspace @securelayer/sdk-node run build
RUN npm --workspace @securelayer/demo-node-app run build

FROM node:22-alpine
WORKDIR /app
COPY --from=build /workspace/node_modules ./node_modules
COPY --from=build /workspace/sdk-node/dist ./node_modules/@securelayer/sdk-node/dist
COPY --from=build /workspace/sdk-node/package.json ./node_modules/@securelayer/sdk-node/package.json
COPY --from=build /workspace/demo-node-app/package.json ./package.json
COPY --from=build /workspace/demo-node-app/dist ./dist

EXPOSE 3001
ENV PORT=3001
CMD ["node", "dist/server.js"]
