const axios = require('axios');
async function dispatch(endpoint) {
  const res = await axios.get(endpoint);
  return res.data;
}
dispatch('https://api.internal/health');
