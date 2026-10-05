import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import process from "node:process";

const backendTarget = process.env.BACKEND_PROXY_URL || "http://127.0.0.1:8080";

export default defineConfig({
  plugins: [react()],

  server: {
    host: true,
    port: 3000,

    proxy: {
      "/api": {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
      },

      "/health/backend": {
        target: backendTarget,
        changeOrigin: true,
        secure: false,
        rewrite: () => "/health",
      },
    },
  },

  build: {
    outDir: "dist",
  },
});
