import { defineConfig } from "vite";

// The Python service (service/server.py) serves the API on 127.0.0.1:8765.
// In development Vite serves the app on :5173 and forwards /api to it.
export default defineConfig({
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    proxy: { "/api": { target: "http://127.0.0.1:8765", changeOrigin: false } },
  },
  build: { outDir: "dist", emptyOutDir: true, sourcemap: false },
});
