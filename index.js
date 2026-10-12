const ngrok = require('@ngrok/ngrok');
const port = Number(process.env.PORT || 3000);

if (!process.env.NGROK_AUTHTOKEN) {
  console.error('NGROK_AUTHTOKEN is required to start the ngrok tunnel.');
  process.exit(1);
}

const server = require('./serve.js');
const options = {
  addr: `localhost:${port}`,
  authtoken_from_env: true,
};

if (process.env.NGROK_DOMAIN) {
  options.domain = process.env.NGROK_DOMAIN;
}

ngrok.forward(options)
  .then((forwarder) => {
    console.log(`Available at: ${forwarder.url()}`);
  })
  .catch((error) => {
    console.error('Failed to start ngrok tunnel:', error);
    server.close(() => {
      process.exitCode = 1;
    });
  });
