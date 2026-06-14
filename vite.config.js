import { defineConfig } from "vite";

export default defineConfig({
  root: "desktop/renderer",
  server: {
    host: "0.0.0.0",
    port: 3000,
    strictPort: true,
    allowedHosts: ["localhost", "127.0.0.1"],
  },
  preview: {
    host: "0.0.0.0",
    port: 3000,
    strictPort: true,
    allowedHosts: ["localhost", "127.0.0.1"],
  },
  build: {
    outDir: "dist",
    emptyOutDir: true,
  },
});
