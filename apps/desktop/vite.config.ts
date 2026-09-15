import { defineConfig } from "vite";

export default defineConfig({
  clearScreen: false,
  preview: { port: 17005, strictPort: true },
  server: {
    port: 16040,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  build: {
    rollupOptions: {
      input: {
        main: "index.html",
        settings: "settings.html",
      },
    },
  },
});
