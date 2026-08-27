'use client';

import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { copyTextToClipboard } from '@/lib/clipboard';

type CopyState = 'idle' | 'copied' | 'failed';
type CopyTarget = 'command' | 'aiPrompt';

interface InstallCommandBlockProps {
  command: string;
  packageName: string;
  client: string;
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
      <span className="install-command-text">{command}</span>
      {'\n\n'}
      <span className="comment"># {String(t('detail.install.ai_prompt_comment'))}</span>
      {'\n'}
      <span className="install-ai-prompt-text">{aiPrompt}</span>
    </div>
  );
}
