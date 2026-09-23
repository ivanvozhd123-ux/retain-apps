// Retain — Cloudflare Worker
// Маршруты:
//   POST /api/auth/login     — логин Apple ID
//   POST /api/auth/2fa       — подтверждение 2FA
//   POST /api/sign/start     — запуск подписи
//   GET  /api/sign/status/:id — статус джоба
//   GET  /udid-profile        — отдаёт .mobileconfig для получения UDID
//   GET  /udid-callback       — Apple сюда отправляет UDID после установки профиля

// ─── КОНФИГ (переменные среды в CF Dashboard) ───────────
// APPLE_TEAM_ID, R2_BUCKET, IPASIGNX_API (если используем как fallback)
// KV namespace: SESSIONS (session_token → { appleId, cookies, udid, ... })
// KV namespace: JOBS     (job_id → { status, steps, installUrl, error })

export default {
  async fetch(request, env, ctx) {
    const url    = new URL(request.url);
    const path   = url.pathname;
    const method = request.method;

    const cors = {
      'Access-Control-Allow-Origin':  '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type',
    };

    if (method === 'OPTIONS') return new Response(null, { headers: cors });

    const json = (data, status = 200) =>
      new Response(JSON.stringify(data), {
        status,
        headers: { 'Content-Type': 'application/json', ...cors },
      });

    try {
      // ── UDID PROFILE ──────────────────────────────────────
      if (path === '/udid-profile' && method === 'GET') {
        return udidProfile(request, env, json);
      }

      if (path === '/udid-callback' && method === 'POST') {
        return udidCallback(request, env, json);
      }

      // ── AUTH ──────────────────────────────────────────────
      if (path === '/api/auth/login' && method === 'POST') {
        return appleLogin(request, env, json);
      }

      if (path === '/api/auth/2fa' && method === 'POST') {
        return apple2FA(request, env, json);
      }

      // ── SIGN ──────────────────────────────────────────────
      if (path === '/api/sign/start' && method === 'POST') {
        return signStart(request, env, ctx, json);
      }

      if (path.startsWith('/api/sign/status/') && method === 'GET') {
        const jobId = path.split('/').pop();
        return signStatus(jobId, env, json);
      }

      // ── SESSION INIT (UDID) ───────────────────────────────
      if (path === '/api/session/init' && method === 'GET') {
        const app = url.searchParams.get('app') || 'unknown';
        // Генерируем временный session ID, сохраняем app
        const sessionId = crypto.randomUUID();
        await env.SESSIONS.put(sessionId, JSON.stringify({ app, udid: null }), { expirationTtl: 3600 });
        // Пока UDID не получен — отдаём пустой (придёт через mobileconfig flow)
        return json({ sessionId, udid: null });
      }

      return json({ error: 'Not found' }, 404);

    } catch (e) {
      return json({ error: e.message }, 500);
    }
  },
};

// ═══════════════════════════════════════════════════════════
// UDID FLOW
// ═══════════════════════════════════════════════════════════

// Отдаём .mobileconfig — Safari его устанавливает и POST-ит UDID обратно
async function udidProfile(request, env, json) {
  const url      = new URL(request.url);
  const callback = `https://${url.host}/udid-callback`;

  const plist = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>PayloadContent</key>
  <dict>
    <key>URL</key>
    <string>${callback}</string>
    <key>DeviceAttributes</key>
    <array>
      <string>UDID</string>
      <string>IMEI</string>
      <string>PRODUCT</string>
      <string>VERSION</string>
      <string>SERIAL</string>
    </array>
  </dict>
  <key>PayloadOrganization</key>
  <string>Retain</string>
  <key>PayloadDisplayName</key>
  <string>Retain — Определение устройства</string>
  <key>PayloadVersion</key>
  <integer>1</integer>
  <key>PayloadUUID</key>
  <string>3C4DC7D2-3B77-4F5A-9B2E-8A1C3D6E9F0A</string>
  <key>PayloadIdentifier</key>
  <string>ru.retain.udid</string>
  <key>PayloadType</key>
  <string>Profile Service</string>
</dict>
</plist>`;

  return new Response(plist, {
    headers: {
      'Content-Type': 'application/x-apple-aspen-config',
      'Content-Disposition': 'attachment; filename="retain-udid.mobileconfig"',
    },
  });
}

// Apple POST-ит сюда plist с UDID после установки профиля
async function udidCallback(request, env, json) {
  const body = await request.text();

  // Парсим UDID из plist (грубый regex — достаточно для этого формата)
  const udidMatch = body.match(/<key>UDID<\/key>\s*<string>([^<]+)<\/string>/);
  const udid = udidMatch ? udidMatch[1].trim() : null;

  if (!udid) return new Response('Bad Request', { status: 400 });

  // Сохраняем UDID по IP (временная привязка до сессии)
  const ip = request.headers.get('CF-Connecting-IP') || 'unknown';
  await env.SESSIONS.put(`udid:${ip}`, udid, { expirationTtl: 600 });

  // Apple ждёт редирект после callback
  return new Response(null, {
    status: 302,
    headers: { Location: '/' },
  });
}

// ═══════════════════════════════════════════════════════════
// APPLE AUTH
// ═══════════════════════════════════════════════════════════

async function appleLogin(request, env, json) {
  const { appleId, password, udid, app } = await request.json();

  if (!appleId || !password) return json({ error: 'Укажите Apple ID и пароль' }, 400);

  // Шаг 1: получить сессионный токен Apple (idmsa.apple.com)
  const initRes = await fetch('https://idmsa.apple.com/appleauth/auth/signin', {
    method: 'POST',
    headers: {
      'Content-Type':   'application/json',
      'Accept':         'application/json',
      'X-Apple-Widget-Key': await getAppleWidgetKey(),
      'X-Apple-OAuth-Client-Id': 'com.apple.gs.xcode.auth',
      'X-Apple-OAuth-Client-Type': 'firstPartyAuth',
      'X-Apple-OAuth-Redirect-URI': 'https://www.apple.com',
      'X-Apple-OAuth-Require-Grant-Code': 'true',
      'X-Apple-OAuth-Response-Mode': 'form_post',
      'X-Apple-OAuth-Response-Type': 'code',
      'X-Apple-OAuth-State': crypto.randomUUID(),
      'User-Agent': 'Xcode/16.0',
    },
    body: JSON.stringify({ accountName: appleId, password, rememberMe: false }),
  });

  const initHeaders = Object.fromEntries(initRes.headers.entries());
  const initBody    = await initRes.json().catch(() => ({}));

  // Сохраняем cookies сессии
  const cookies = initHeaders['set-cookie'] || '';
  const sessionId = crypto.randomUUID();

  // Apple возвращает 409 если нужен 2FA
  if (initRes.status === 409 || initBody.authType === 'hsa2') {
    await env.SESSIONS.put(sessionId, JSON.stringify({
      appleId, udid: udid || '', app,
      cookies,
      scnt: initHeaders['x-apple-id-account-country'] || '',
      sessionToken: initHeaders['x-apple-session-token'] || '',
      twoSVTrustEligible: initBody.twoSVTrustEligible || false,
    }), { expirationTtl: 600 });

    return json({ requires2FA: true, sessionToken: sessionId });
  }

  if (initRes.status === 200) {
    // Логин без 2FA — редкость, но обрабатываем
    await env.SESSIONS.put(sessionId, JSON.stringify({
      appleId, udid: udid || '', app, cookies,
      authenticated: true,
    }), { expirationTtl: 600 });
    return json({ success: true, sessionToken: sessionId });
  }

  // Ошибки: неверный пароль, блокировка и т.д.
  const errMsg = initBody.serviceErrors?.[0]?.message || 'Неверный Apple ID или пароль';
  return json({ error: errMsg }, 401);
}

async function apple2FA(request, env, json) {
  const { code, sessionToken } = await request.json();

  const raw = await env.SESSIONS.get(sessionToken);
  if (!raw) return json({ error: 'Сессия истекла' }, 401);
  const session = JSON.parse(raw);

  // Отправляем код в Apple
  const verifyRes = await fetch('https://idmsa.apple.com/appleauth/auth/verify/trusteddevice/securitycode', {
    method: 'POST',
    headers: {
      'Content-Type':   'application/json',
      'Accept':         'application/json',
      'Cookie':         session.cookies,
      'X-Apple-Widget-Key': await getAppleWidgetKey(),
      'scnt': session.scnt || '',
    },
    body: JSON.stringify({ securityCode: { code } }),
  });

  if (verifyRes.status !== 204 && verifyRes.status !== 200) {
    return json({ error: 'Неверный код' }, 401);
  }

  // Получаем итоговые cookies после 2FA
  const newCookies = verifyRes.headers.get('set-cookie') || session.cookies;

  // Обновляем сессию
  session.authenticated = true;
  session.cookies = newCookies;
  await env.SESSIONS.put(sessionToken, JSON.stringify(session), { expirationTtl: 600 });

  return json({ success: true, sessionToken });
}

// ═══════════════════════════════════════════════════════════
// SIGNING FLOW
// ═══════════════════════════════════════════════════════════

async function signStart(request, env, ctx, json) {
  const { sessionToken, app, udid } = await request.json();

  const raw = await env.SESSIONS.get(sessionToken);
  if (!raw) return json({ error: 'Сессия истекла' }, 401);
  const session = JSON.parse(raw);
  if (!session.authenticated) return json({ error: 'Не авторизован' }, 401);

  const jobId = crypto.randomUUID();

  // Начальный статус
  await env.JOBS.put(jobId, JSON.stringify({
    status: 'running',
    steps: ['active', 'pending', 'pending', 'pending'],
    installUrl: null,
    error: null,
  }), { expirationTtl: 1800 });

  // Запускаем фоновую задачу
  ctx.waitUntil(runSigningJob(jobId, session, app, udid || session.udid, env));

  return json({ jobId });
}

async function signStatus(jobId, env, json) {
  const raw = await env.JOBS.get(jobId);
  if (!raw) return json({ error: 'Job not found' }, 404);
  return json(JSON.parse(raw));
}

// ─── ОСНОВНАЯ ЦЕПОЧКА ПОДПИСИ ─────────────────────────────
async function runSigningJob(jobId, session, appSlug, udid, env) {
  const update = async (stepIdx, stepStatus, jobStatus = 'running', extra = {}) => {
    const raw  = await env.JOBS.get(jobId);
    const job  = JSON.parse(raw);
    job.steps[stepIdx] = stepStatus;
    job.status = jobStatus;
    Object.assign(job, extra);
    await env.JOBS.put(jobId, JSON.stringify(job), { expirationTtl: 1800 });
  };

  try {
    // ── Шаг 0: авторизация Apple Developer ────────────────
    await update(0, 'active');
    const devSession = await getDevSession(session.cookies, session.appleId);
    await update(0, 'done');

    // ── Шаг 1: создание сертификата ───────────────────────
    await update(1, 'active');
    const { p12Base64, p12Password } = await createCertificate(devSession, env);
    await update(1, 'done');

    // ── Шаг 2: регистрация устройства + provisioning profile
    await update(2, 'active');
    const { provisionBase64 } = await createProvisioningProfile(devSession, udid, appSlug, env);
    await update(2, 'done');

    // ── Шаг 3: подпись через IPASignX ─────────────────────
    await update(3, 'active');
    const installUrl = await signWithIPASignX(appSlug, p12Base64, p12Password, provisionBase64, env);
    await update(3, 'done', 'done', { installUrl });

  } catch (e) {
    const raw = await env.JOBS.get(jobId);
    const job = JSON.parse(raw);
    const activeIdx = job.steps.findIndex(s => s === 'active');
    if (activeIdx >= 0) job.steps[activeIdx] = 'error';
    job.status = 'error';
    job.error  = e.message;
    await env.JOBS.put(jobId, JSON.stringify(job), { expirationTtl: 1800 });
  }
}

// ─── APPLE DEVELOPER SESSION ──────────────────────────────
async function getDevSession(cookies, appleId) {
  // Получаем CSRF токен и сессию Apple Developer
  const res = await fetch('https://developer.apple.com/services-account/QH65B2/account/ios/certificate/listCertRequests.action', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie': cookies,
      'X-Requested-With': 'XMLHttpRequest',
      'Accept': 'application/json',
    },
    body: 'teamId=&pageNumber=1&pageSize=20&sort=name%3Dasc&certificateType=IOS_DEVELOPMENT',
  });

  const data = await res.json();
  return {
    cookies,
    teamId: data.certRequests?.[0]?.teamId || '',
    csrf:   res.headers.get('csrf') || '',
  };
}

// ─── СОЗДАНИЕ СЕРТИФИКАТА ─────────────────────────────────
async function createCertificate(devSession, env) {
  // Генерируем RSA ключевую пару через WebCrypto
  const keyPair = await crypto.subtle.generateKey(
    { name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: new Uint8Array([1,0,1]), hash: 'SHA-256' },
    true,
    ['sign', 'verify']
  );

  // Экспортируем приватный ключ
  const privKeyDer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const pubKeyDer  = await crypto.subtle.exportKey('spki',  keyPair.publicKey);

  // Создаём CSR (минимальный DER — Apple принимает)
  const csr = buildCSR(pubKeyDer, privKeyDer, keyPair.privateKey);

  // Отправляем CSR в Apple Developer
  const csrB64 = btoa(String.fromCharCode(...new Uint8Array(await csr)));

  const submitRes = await fetch('https://developer.apple.com/services-account/QH65B2/account/ios/certificate/submitCertificateRequest.action', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie':  devSession.cookies,
      'csrf':    devSession.csrf,
    },
    body: new URLSearchParams({
      csrContent: csrB64,
      teamId:     devSession.teamId,
      type:       'IOS_DEVELOPMENT',
      subPlatform:'',
      pageNumber: '1',
      pageSize:   '20',
      sort:       'name=asc',
    }),
  });

  const certData = await submitRes.json();
  const certDer  = certData.certRequest?.certContent;
  if (!certDer) throw new Error('Не удалось создать сертификат');

  // Собираем .p12 из privKey + cert
  const password  = generatePassword();
  const p12Base64 = await buildP12(privKeyDer, certDer, password);

  return { p12Base64, p12Password: password };
}

// ─── PROVISIONING PROFILE ─────────────────────────────────
async function createProvisioningProfile(devSession, udid, appSlug, env) {
  // 1. Регистрируем UDID устройства
  await fetch('https://developer.apple.com/services-account/QH65B2/account/ios/device/addDevice.action', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie':  devSession.cookies,
      'csrf':    devSession.csrf,
    },
    body: new URLSearchParams({
      deviceNumber: udid,
      name:         'Retain Device',
      teamId:       devSession.teamId,
    }),
  });

  // 2. Создаём App ID (wildcard)
  const bundleId = `ru.retain.${appSlug}.*`;
  await fetch('https://developer.apple.com/services-account/QH65B2/account/ios/identifiers/addAppId.action', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie':  devSession.cookies,
      'csrf':    devSession.csrf,
    },
    body: new URLSearchParams({
      name:           `Retain ${appSlug}`,
      appIdName:      `Retain ${appSlug}`,
      identifier:     bundleId,
      type:           'explicit',
      teamId:         devSession.teamId,
      features:       '',
    }),
  });

  // 3. Создаём provisioning profile
  const profileRes = await fetch('https://developer.apple.com/services-account/QH65B2/account/ios/profile/createProvisioningProfile.action', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/x-www-form-urlencoded',
      'Cookie':  devSession.cookies,
      'csrf':    devSession.csrf,
    },
    body: new URLSearchParams({
      provisioningProfileName: `Retain ${appSlug}`,
      appIdId:                 bundleId,
      distributionType:        'limited',
      deviceIds:               udid,
      teamId:                  devSession.teamId,
    }),
  });

  const profileData   = await profileRes.json();
  const provisionB64  = profileData.provisioningProfile?.encodedProfile;
  if (!provisionB64) throw new Error('Не удалось создать provisioning profile');

  return { provisionBase64: provisionB64 };
}

// ─── ПОДПИСЬ ЧЕРЕЗ IPASIGNX ───────────────────────────────
async function signWithIPASignX(appSlug, p12Base64, p12Password, provisionBase64, env) {
  // Получаем URL .ipa из R2
  const ipaUrl = `https://${env.R2_PUBLIC_URL}/apps/${appSlug}.ipa`;

  const form = new FormData();
  form.append('ipa_url',    ipaUrl);
  form.append('p12',        base64ToBlob(p12Base64,       'application/x-pkcs12'), 'cert.p12');
  form.append('mobileprovision', base64ToBlob(provisionBase64, 'application/octet-stream'), 'retain.mobileprovision');
  form.append('p12_password', p12Password);

  // Upload на IPASignX
  const uploadRes = await fetch('https://sign.ipasign.cc/api/upload', {
    method: 'POST',
    body:   form,
  });

  const uploadData = await uploadRes.json();
  if (!uploadData.success) throw new Error('IPASignX upload failed');

  // Ждём завершения подписи (polling)
  const taskId = uploadData.taskId;
  for (let i = 0; i < 30; i++) {
    await sleep(3000);
    const statusRes  = await fetch(`https://sign.ipasign.cc/api/status/${taskId}`);
    const statusData = await statusRes.json();

    if (statusData.status === 'done') {
      // Строим OTA манифест и отдаём itms-services:// ссылку
      const signedUrl  = statusData.downloadUrl;
      const manifestUrl = await uploadManifest(signedUrl, appSlug, env);
      return `itms-services://?action=download-manifest&url=${encodeURIComponent(manifestUrl)}`;
    }

    if (statusData.status === 'error') throw new Error('Ошибка подписи на IPASignX');
  }

  throw new Error('Таймаут подписи');
}

// ─── OTA MANIFEST ─────────────────────────────────────────
async function uploadManifest(ipaUrl, appSlug, env) {
  const APP_META = {
    vtb:       { name: 'ВТБ Онлайн',  bundle: 'ru.vtb.online'      },
    sber:      { name: 'СберБанк',    bundle: 'ru.sber.mobile'     },
    gosuslugi: { name: 'Госуслуги',   bundle: 'ru.gosuslugi.app'   },
    tinkoff:   { name: 'Т-Банк',      bundle: 'ru.tinkoff.mobile'  },
    mir:       { name: 'Mir Pay',      bundle: 'ru.nspk.mirpay'     },
  };

  const meta   = APP_META[appSlug] || { name: appSlug, bundle: `ru.retain.${appSlug}` };
  const manifest = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>items</key>
  <array>
    <dict>
      <key>assets</key>
      <array>
        <dict>
          <key>kind</key><string>software-package</string>
          <key>url</key><string>${ipaUrl}</string>
        </dict>
      </array>
      <key>metadata</key>
      <dict>
        <key>bundle-identifier</key><string>${meta.bundle}</string>
        <key>bundle-version</key><string>1.0</string>
        <key>kind</key><string>software</string>
        <key>title</key><string>${meta.name}</string>
      </dict>
    </dict>
  </array>
</dict>
</plist>`;

  const manifestKey = `manifests/${appSlug}-${Date.now()}.plist`;
  await env.R2_BUCKET.put(manifestKey, manifest, {
    httpMetadata: { contentType: 'application/xml' },
  });

  return `https://${env.R2_PUBLIC_URL}/${manifestKey}`;
}

// ═══════════════════════════════════════════════════════════
// CRYPTO HELPERS
// ═══════════════════════════════════════════════════════════

// Минимальный DER CSR для Apple Developer
// В продакшне: использовать готовую WASM библиотеку (forge.wasm или pkijs)
async function buildCSR(pubKeyDer, privKeyDer, privateKey) {
  // Заглушка — в реальности нужен pkijs или forge в WASM
  // Возвращает ArrayBuffer с DER-encoded CSR
  // TODO: интегрировать pkijs
  return pubKeyDer;
}

// Сборка PKCS#12 (.p12) из приватного ключа и сертификата
// В продакшне: pkijs или node-forge в WASM
async function buildP12(privKeyDer, certDer, password) {
  // TODO: интегрировать pkijs/forge WASM
  // Сейчас возвращает base64 заглушку
  return btoa(String.fromCharCode(...new Uint8Array(privKeyDer)));
}

function generatePassword() {
  const chars = 'ABCDEFGHJKMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789';
  return Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => chars[b % chars.length]).join('');
}

function base64ToBlob(b64, type) {
  const bin = atob(b64);
  const buf = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) buf[i] = bin.charCodeAt(i);
  return new Blob([buf], { type });
}

async function getAppleWidgetKey() {
  // Статичный ключ Xcode — может меняться с версией Xcode
  return 'e0b80c3bf78523bfe80974d320935bfa30add02e1bef6658e3866567213c6b0c';
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
