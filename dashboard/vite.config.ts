import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";
import { viteSingleFile } from "vite-plugin-singlefile";

export default defineConfig({
  plugins: [react(), tailwindcss(), viteSingleFile()],
  base: "/dashboard/",
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/ipam": "http://localhost:8080",
      "/v4": "http://localhost:8080",
      "/v6": "http://localhost:8080",
      "/batch": "http://localhost:8080",
      "/health": "http://localhost:8080",
      "/version": "http://localhost:8080",
      "/features": "http://localhost:8080",
    },
  },
});
