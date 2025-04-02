/**
 * Welcome to Cloudflare Workers! This is your first worker.
 *
 * - Run "npm run dev" in your terminal to start a development server
 * - Open a browser tab at http://localhost:8787/ to see your worker in action
 * - Run "npm run deploy" to publish your worker
 *
 * Learn more at https://developers.cloudflare.com/workers/
 */

async function fetchOIDCAccessToken(client_id, client_secret, grant_type, code) {
  const response = await fetch('https://api.dingtalk.com/v1.0/oauth2/userAccessToken', {
      method: 'POST',
      headers: {
          'Content-Type': 'application/json'
      },
      body: JSON.stringify({
          clientId: client_id,
          clientSecret: client_secret,
          code: code,
          grantType: grant_type,
      })
  });
  return response.json();
}

async function fetchUserInfo(access_token) {
  const response = await fetch('https://api.dingtalk.com/v1.0/contact/users/me', {
      method: 'GET',
      headers: {
          'x-acs-dingtalk-access-token': access_token,
          'Content-Type': 'application/json'
      },
  });
  return response.json();
}

async function handleRequest(request) {
  if (request.method !== 'POST') {
      return new Response('Method Not Allowed', { status: 405 });
  }

  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Basic ')) {
      return new Response('Unauthorized', { status: 401 });
  }

  const base64Credentials = authHeader.split(' ')[1];
  const credentials = atob(base64Credentials).split(':');
  const client_id = credentials[0];
  const client_secret = credentials[1];

  const formData = await request.formData();
  const body = {};
  for (const entry of formData.entries()) {
        body[entry[0]] = entry[1];
    }
  const { redirect_uri, code, grant_type } = body;

  // 2.获取 OIDC access_token
  const oidcResponse = await fetchOIDCAccessToken(client_id, client_secret, grant_type, code);

  // 返回响应中的 data
  var newBody = {
    access_token: oidcResponse.accessToken,
    refresh_token: oidcResponse.refreshToken,
    token_type: "Bearer",
    expires_in: oidcResponse.expireIn,
  };
  return new Response(JSON.stringify(newBody), {
      headers: { 'Content-Type': 'application/json' }
  });
}

async function handleRequest2(request) {
    // 检查请求方法是否为 GET
    if (request.method !== 'GET') {
      return new Response('Method Not Allowed', { status: 405 })
    }

    const authHeader = request.headers.get('Authorization');
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return new Response('Unauthorized', { status: 401 });
    }
  
    const access_token = authHeader.split(' ')[1];

      // 2.获取 OIDC access_token
    const oidcResponse = await fetchUserInfo(access_token);

    // 返回响应中的 data
    oidcResponse.union_id = oidcResponse.unionId;
    oidcResponse.sub = oidcResponse.unionId;
    oidcResponse.id = oidcResponse.unionId;
    return new Response(JSON.stringify(oidcResponse), {
        headers: { 'Content-Type': 'application/json' }
    });
  }

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (url.pathname === '/oauth2/token' && request.method === 'POST') {
        return handleRequest(request);
    }
    if (url.pathname === '/oauth2/user_info' && request.method === 'GET') {
        return handleRequest2(request);
    }
    return new Response('Unauthorized', { status: 401 });
  },
};
