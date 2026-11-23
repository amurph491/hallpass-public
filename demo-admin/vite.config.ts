import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Override to reach a running Compose stack, e.g. HALLPASS_API_PROXY=http://localhost:3000
      "/api": process.env.HALLPASS_API_PROXY ?? "http://localhost:8080"
    }
  }
});
