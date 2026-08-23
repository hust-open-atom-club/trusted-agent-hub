'use client';

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';

type CopyState = 'idle' | 'copied' | 'failed';

interface InstallCommandBlockProps {
  command: string;
  packageName: string;
}

export default function InstallCommandBlock({ command, packageName }: InstallCommandBlockProps) {
  const { t } = useTranslation();
  const [copyState, setCopyState] = useState<CopyState>('idle');
  const resetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    setCopyState('idle');
  }, [command]);

  useEffect(() => () => {
    if (resetTimer.current) {
      clearTimeout(resetTimer.current);
    }
  }, []);

  const scheduleReset = () => {
    if (resetTimer.current) {
      clearTimeout(resetTimer.current);
    }

    resetTimer.current = setTimeout(() => {
      setCopyState('idle');
      resetTimer.current = null;
    }, 1800);
  };

  const copyCommand = async () => {
    try {
      if (!navigator.clipboard?.writeText) {
        throw new Error('Clipboard API unavailable');
      }

      await navigator.clipboard.writeText(command);
      setCopyState('copied');
    } catch {
      setCopyState('failed');
    } finally {
      scheduleReset();
    }
  };

  const buttonLabel =
    copyState === 'copied'
      ? String(t('detail.install.copied'))
      : copyState === 'failed'
        ? String(t('detail.install.copy_failed'))
        : String(t('detail.install.copy_command'));

  return (
    <div className="install-block install-command-block">
      <button
        type="button"
        className={`install-copy-btn ${copyState}`}
        onClick={copyCommand}
        aria-label={buttonLabel}
      >
        {buttonLabel}
      </button>
      <span className="comment"># {String(t('detail.install.command_comment', { name: packageName }))}</span>
      {'\n'}
      <span className="install-command-text">{command}</span>
    </div>
  );
}
