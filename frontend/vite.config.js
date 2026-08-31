import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

import {
  parseInjectedBuildIdentity,
  sourceVersion,
} from "../scripts/release/build-identity.mjs";
import { developmentBuildIdentity } from "./src/buildIdentityContract.js";

const buildIdentity = parseInjectedBuildIdentity(process.env)
  ?? developmentBuildIdentity(sourceVersion());

export default defineConfig({
  plugins: [react()],
  define: {
    __GLACIAL_BUILD_IDENTITY__: JSON.stringify(buildIdentity),
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    strictPort: true,
    watch: {
      ignored: ["**/src-tauri/**"],
    },
  },
  preview: {
    strictPort: false,
  },
});
