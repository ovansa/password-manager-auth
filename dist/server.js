"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const app_1 = require("./app");
const logger_1 = require("./helpers/logger");
const PORT = process.env.PORT ?? 3000;
const ENV = process.env.NODE_ENV ?? 'development';
const isProd = ENV === 'production';
// ANSI helpers
const c = {
    reset: '\x1b[0m',
    bold: '\x1b[1m',
    dim: '\x1b[2m',
    cyan: '\x1b[36m',
    green: '\x1b[32m',
    yellow: '\x1b[33m',
    gray: '\x1b[90m',
    white: '\x1b[97m',
};
function printBanner(port) {
    if (isProd)
        return; // clean logs in production
    const url = `http://localhost:${port}`;
    console.log(`
${c.cyan}${c.bold}  ██████╗  █████╗ ███████╗███████╗ █████╗ ${c.reset}
${c.cyan}${c.bold}  ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔══██╗${c.reset}
${c.cyan}${c.bold}  ██████╔╝███████║███████╗███████╗███████║${c.reset}
${c.cyan}${c.bold}  ██╔═══╝ ██╔══██║╚════██║╚════██║██╔══██║${c.reset}
${c.cyan}${c.bold}  ██║     ██║  ██║███████║███████║██║  ██║${c.reset}
${c.cyan}${c.bold}  ╚═╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝${c.reset}
${c.gray}  Password Manager Auth Server${c.reset}
${c.gray}  ─────────────────────────────────────────${c.reset}
  ${c.gray}url   ${c.reset}${c.white}${c.bold}${url}${c.reset}
  ${c.gray}env   ${c.reset}${c.yellow}${ENV}${c.reset}
  ${c.gray}port  ${c.reset}${c.white}${port}${c.reset}
${c.gray}  ─────────────────────────────────────────${c.reset}
`);
}
app_1.app.listen(PORT, () => {
    printBanner(PORT);
    logger_1.logger.info('server.ready', {
        port: PORT,
        env: ENV,
    });
});
