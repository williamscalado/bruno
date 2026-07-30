require('dotenv').config({ path: process.env.DOTENV_PATH });
const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');
const notarize = require('./notarize');

const entitlementsPath = path.join(__dirname, 'resources', 'entitlements.mac.plist');

const hasNotarizationCredentials = () => Boolean(process.env.APPLE_ID && process.env.APPLE_ID_PASSWORD);

/**
 * macOS gates local network access per application (System Settings > Privacy & Security > Local
 * Network) and identifies the application by its code signature. A bundle without a sealed
 * signature has no stable identity, so the grant can never be persisted and connecting to a LAN
 * address fails with EHOSTUNREACH — with no prompt and nothing in the system log.
 *
 * electron-builder skips signing altogether when no Apple Developer identity is available, which
 * leaves exactly that bundle behind. Sealing it with an ad-hoc signature gives macOS an identity to
 * anchor the permission to. The signature is only valid on the machine that produced it, so this is
 * for local builds; release builds go through notarization instead.
 */
const signAdHoc = (appPath) => {
  execFileSync(
    'codesign',
    [
      '--force',
      '--deep',
      '--sign',
      '-',
      '--options',
      'runtime',
      '--entitlements',
      entitlementsPath,
      '--timestamp=none',
      appPath
    ],
    { stdio: 'inherit' }
  );
  execFileSync('codesign', ['--verify', '--verbose=2', appPath], { stdio: 'inherit' });
};

const afterSign = async function (params) {
  if (process.platform !== 'darwin') {
    return;
  }

  const appPath = path.join(params.appOutDir, `${params.packager.appInfo.productFilename}.app`);
  if (!fs.existsSync(appPath)) {
    console.error(`Cannot find application at: ${appPath}`);
    return;
  }

  if (hasNotarizationCredentials()) {
    return notarize(params);
  }

  console.log(`Ad-hoc signing ${appPath}`);
  signAdHoc(appPath);
  console.log(`Done ad-hoc signing ${appPath}`);
};

module.exports = afterSign;
