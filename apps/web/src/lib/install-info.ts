/**
 * Install method display helpers for the package detail page.
 */

export interface InstallMethodInfo {
  key: string;
  label: string;
  description: string;
  /** npm/pip/docker 会执行外部命令，安装时需要显式确认。 */
  requiresExternalCommand: boolean;
}

const INSTALL_METHODS: Record<string, InstallMethodInfo> = {
  copy_directory: {
    key: 'copy_directory',
    label: '目录复制',
    description: '下载 ZIP 并校验 SHA-256 后，复制到目标客户端目录。',
    requiresExternalCommand: false,
  },
  npm_install: {
    key: 'npm_install',
    label: 'npm 安装',
    description: '通过 npm 安装到受管目录 ~/.trusted-agent-hub/installed/<name>-npm，不污染系统环境。',
    requiresExternalCommand: true,
  },
  pip_install: {
    key: 'pip_install',
    label: 'pip 安装',
    description: '通过 pip 安装到受管目录 ~/.trusted-agent-hub/installed/<name>-pip。',
    requiresExternalCommand: true,
  },
  docker_run: {
    key: 'docker_run',
    label: 'Docker',
    description: '拉取镜像并生成运行配置（不会自动启动容器）。',
    requiresExternalCommand: true,
  },
  manual_steps: {
    key: 'manual_steps',
    label: '人工步骤',
    description: '按包说明手动完成安装，CLI 只记录步骤。',
    requiresExternalCommand: false,
  },
};

export function getInstallMethodInfo(
  method?: string | null,
): InstallMethodInfo {
  return (
    INSTALL_METHODS[method ?? ''] ?? {
      key: method ?? 'unknown',
      label: method ?? '未知',
      description: '按包说明完成安装。',
      requiresExternalCommand: false,
    }
  );
}

/**
 * 生成可直接复制执行的安装命令：
 * - 包只兼容非默认客户端（如 claude-code-plugin）时自动带 --client；
 * - npm/pip/docker 外部命令方式自动带 --yes（显式确认）。
 */
export function buildInstallCommand(
  packageName: string,
  compatibility: string[] = [],
  method?: string | null,
): string {
  const client =
    compatibility.length === 1 && compatibility[0] !== 'claude-code'
      ? ` --client ${compatibility[0]}`
      : '';
  const confirm = ['npm_install', 'pip_install', 'docker_run'].includes(
    method ?? '',
  )
    ? ' --yes'
    : '';
  return `tah install ${packageName}${client}${confirm}`;
}
