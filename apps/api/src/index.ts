import { createApp } from "./app.js";
import { loadConfig } from "./config.js";

const config = loadConfig();
// Der Bot-Token der Telegram-Freigabe lebt nur in config; Kindprozesse
// (opencode, copilot, tmux) erben process.env und sollen ihn nie sehen.
delete process.env.COCKPIT_TELEGRAM_BOT_TOKEN;
const app = await createApp({ config });

try {
  await app.listen({ host: config.apiHost, port: config.apiPort });
  console.log(`control-api listening on http://${config.apiHost}:${config.apiPort}`);
} catch (error) {
  app.log.error(error);
  process.exit(1);
}

