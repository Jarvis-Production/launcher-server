export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const target = 'https://launcher-server-wl84.onrender.com' + url.pathname + url.search;

    const headers = new Headers(request.headers);
    headers.set('Host', 'launcher-server-wl84.onrender.com');
    headers.delete('cf-connecting-ip');
    headers.delete('cf-ipcountry');
    headers.delete('cf-ray');
    headers.delete('cf-visitor');

    const init = {
      method: request.method,
      headers: headers,
      redirect: 'follow',
    };

    if (request.method === 'POST' || request.method === 'PUT' || request.method === 'PATCH') {
      init.body = await request.arrayBuffer();
    }

    try {
      const response = await fetch(target, init);
      const resHeaders = new Headers(response.headers);
      resHeaders.set('Access-Control-Allow-Origin', '*');
      resHeaders.set('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
      resHeaders.set('Access-Control-Allow-Headers', 'Content-Type, Authorization');

      return new Response(response.body, {
        status: response.status,
        statusText: response.statusText,
        headers: resHeaders,
      });
    } catch (err) {
      return new Response(JSON.stringify({ error: 'Proxy error: ' + err.message }), {
        status: 502,
        headers: { 'Content-Type': 'application/json' },
      });
    }
  },
};
