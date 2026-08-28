'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { copyTextToClipboard } from '@/lib/clipboard';

type CopyState = 'idle' | 'copied' | 'failed';
type CopyTarget = 'command' | 'aiPrompt';

const COMMAND_DISPLAY_LIMIT = 96;
const AI_PROMPT_DISPLAY_LIMIT = 220;

interface InstallCommandBlockProps {
  command: string;
  packageName: string;
  client: string;
}

function truncateDisplayText(value: string, limit: number): string {
  if (value.length <= limit) {
    return value;
  }

  return `${value.slice(0, Math.max(0, limit - 3)).trimEnd()}...`;
}

export default function InstallCommandBlock({ command, packageName, client }: InstallCommandBlockProps) {
  const { t } = useTranslation();
  const [copyState, setCopyState] = useState<Record<CopyTarget, CopyState>>({
    command: 'idle',
    aiPrompt: 'idle',
  });
  const [origin, setOrigin] = useState('');
  const resetTimers = useRef<Partial<Record<CopyTarget, ReturnType<typeof setTimeout>>>>({});

  useEffect(() => {
    setOrigin(window.location.origin);
  }, []);

  useEffect(() => {
    setCopyState({ command: 'idle', aiPrompt: 'idle' });
  }, [command, packageName, client]);

  useEffect(() => () => {
    for (const timer of Object.values(resetTimers.current)) {
      clearTimeout(timer);
    }
  }, []);

  const installGuideUrl = origin ? `${origin}/install/tah.md` : '/install/tah.md';

  const aiPrompt = useMemo(
    () => String(t('detail.install.ai_prompt', {
      guideUrl: installGuideUrl,
      name: packageName,
      client,
    })),
    [client, installGuideUrl, packageName, t],
  );
  const displayCommand = useMemo(() => truncateDisplayText(command, COMMAND_DISPLAY_LIMIT), [command]);
  const displayAiPrompt = useMemo(() => truncateDisplayText(aiPrompt, AI_PROMPT_DISPLAY_LIMIT), [aiPrompt]);

  const scheduleReset = (target: CopyTarget) => {
    if (resetTimers.current[target]) {
      clearTimeout(resetTimers.current[target]);
    }

    resetTimers.current[target] = setTimeout(() => {
      setCopyState((current) => ({ ...current, [target]: 'idle' }));
      delete resetTimers.current[target];
    }, 1800);
  };

  const copyText = async (target: CopyTarget, text: string) => {
    const copied = await copyTextToClipboard(text);
    if (copied) {
      setCopyState((current) => ({ ...current, [target]: 'copied' }));
    } else {
      setCopyState((current) => ({ ...current, [target]: 'failed' }));
    }
    scheduleReset(target);
  };

  const commandButtonLabel =
    copyState.command === 'copied'
      ? String(t('detail.install.copied'))
      : copyState.command === 'failed'
        ? String(t('detail.install.copy_failed'))
        : String(t('detail.install.copy_command'));
  const aiButtonLabel =
    copyState.aiPrompt === 'copied'
      ? String(t('detail.install.copied'))
      : copyState.aiPrompt === 'failed'
        ? String(t('detail.install.copy_failed'))
        : String(t('detail.install.copy_ai_prompt'));

  return (
    <div className="install-block install-command-block">
      <div className="install-copy-actions">
        <button
          type="button"
          className={`install-copy-btn ${copyState.aiPrompt}`}
          onClick={() => copyText('aiPrompt', aiPrompt)}
          aria-label={aiButtonLabel}
        >
          {aiButtonLabel}
        </button>
        <button
          type="button"
          className={`install-copy-btn ${copyState.command}`}
          onClick={() => copyText('command', command)}
          aria-label={commandButtonLabel}
        >
          {commandButtonLabel}
        </button>
      </div>
      <span className="comment"># {String(t('detail.install.command_comment', { name: packageName }))}</span>
      {'\n'}
      <span className="install-command-text" title={command}>{displayCommand}</span>
      {'\n\n'}
      <span className="comment"># {String(t('detail.install.ai_prompt_comment'))}</span>
      {'\n'}
      <span className="install-ai-prompt-text" title={aiPrompt}>{displayAiPrompt}</span>
    </div>
  );
}
