// 端到端扫码测试：Edge 无头 + 假摄像头注入斜码图
// 验证 wasm 解码链路：打开相机 → 识别 → 出结果页
import { chromium } from 'playwright-core';

const IMG = process.argv[2] || 'D:/vsProjects/rollcall-proxy/_fake.y4m';
const browser = await chromium.launch({
  channel: 'msedge',
  headless: true,
  args: [
    '--use-fake-device-for-media-stream',
    `--use-file-for-fake-video-stream=${IMG}`,
    '--autoplay-policy=no-user-gesture-required',
  ],
});
const ctx = await browser.newContext({ permissions: ['camera'], viewport: { width: 400, height: 820 } });
const page = await ctx.newPage();
page.on('console', m => console.log('[console]', m.type(), m.text().slice(0, 200)));
page.on('pageerror', e => console.log('[pageerror]', String(e).slice(0, 300)));

await page.goto('http://localhost:8200/', { waitUntil: 'load' });
await page.fill('#loginId', '2099bt0001');
await page.fill('#loginPwd', 'x');
await page.click('#auth-login button.btn-primary');
await page.waitForTimeout(1500);

await page.locator('.group-item').first().click();
await page.waitForTimeout(800);
await page.locator('.fake-btn.scan').click();
console.log('[test] scanner opened, waiting for decode...');

try {
  await page.waitForSelector('#resultOverlay.open', { timeout: 25000 });
  const title = await page.textContent('#resTitle');
  const sub = await page.textContent('#resSub');
  console.log('[test] RESULT PAGE:', title, '|', sub);
  const cls = await page.getAttribute('#resultOverlay', 'class');
  console.log('[test] overlay class:', cls);
} catch {
  const status = await page.textContent('#gScanStatus').catch(() => '(n/a)');
  const overlay = await page.getAttribute('#scannerOverlay', 'class').catch(() => '?');
  console.log('[test] TIMEOUT. scanner overlay:', overlay, '| status:', status);
}
await page.waitForTimeout(500);
await browser.close();
