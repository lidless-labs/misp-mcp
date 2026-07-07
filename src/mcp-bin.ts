import { serveMcp } from "./mcp-server.js";
import { safeCaughtErrorMessage } from "./safe-error.js";

serveMcp().catch((error: unknown) => {
  console.error("Fatal error:", safeCaughtErrorMessage(error, "Unexpected error"));
  process.exit(1);
});
