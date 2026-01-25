import { homedir, platform } from 'os';
import { join } from 'path';

export function getClaudeConfigPath(): string {
  const home = homedir();
  const os = platform();

  if (os === 'darwin') {
    return join(home, 'Library', 'Application Support', 'Claude', 'claude_desktop_config.json');
  } else if (os === 'win32') {
    return join(home, 'AppData', 'Roaming', 'Claude', 'claude_desktop_config.json');
  } else {
    // Linux
    return join(home, '.config', 'claude', 'claude_desktop_config.json');
  }
}

export function getMCPGuardConfigDir(): string {
  const home = homedir();
  return join(home, '.mcpguard');
}

export function getMCPGuardCacheDir(): string {
  return join(getMCPGuardConfigDir(), 'cache');
}
