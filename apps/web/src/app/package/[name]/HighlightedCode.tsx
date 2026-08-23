'use client';

import hljs from 'highlight.js/lib/core';
import bash from 'highlight.js/lib/languages/bash';
import css from 'highlight.js/lib/languages/css';
import dockerfile from 'highlight.js/lib/languages/dockerfile';
import ini from 'highlight.js/lib/languages/ini';
import javascript from 'highlight.js/lib/languages/javascript';
import json from 'highlight.js/lib/languages/json';
import makefile from 'highlight.js/lib/languages/makefile';
import markdown from 'highlight.js/lib/languages/markdown';
import python from 'highlight.js/lib/languages/python';
import typescript from 'highlight.js/lib/languages/typescript';
import xml from 'highlight.js/lib/languages/xml';
import yaml from 'highlight.js/lib/languages/yaml';

hljs.registerLanguage('bash', bash);
hljs.registerLanguage('css', css);
hljs.registerLanguage('dockerfile', dockerfile);
hljs.registerLanguage('ini', ini);
hljs.registerLanguage('javascript', javascript);
hljs.registerLanguage('json', json);
hljs.registerLanguage('makefile', makefile);
hljs.registerLanguage('markdown', markdown);
hljs.registerLanguage('python', python);
hljs.registerLanguage('typescript', typescript);
hljs.registerLanguage('xml', xml);
hljs.registerLanguage('yaml', yaml);

interface HighlightedCodeProps {
  content: string;
  extension: string;
  path: string;
  maxLines?: number;
  renderLimitNotice?: string;
}

const LANGUAGE_BY_EXTENSION: Record<string, string> = {
  bash: 'bash',
  conf: 'ini',
  css: 'css',
  dockerfile: 'dockerfile',
  env: 'ini',
  htm: 'xml',
  html: 'xml',
  ini: 'ini',
  js: 'javascript',
  jsx: 'javascript',
  json: 'json',
  lock: 'json',
  makefile: 'makefile',
  md: 'markdown',
  mjs: 'javascript',
  py: 'python',
  sh: 'bash',
  toml: 'ini',
  ts: 'typescript',
  tsx: 'typescript',
  xml: 'xml',
  yaml: 'yaml',
  yml: 'yaml',
};

const LANGUAGE_BY_FILENAME: Record<string, string> = {
  dockerfile: 'dockerfile',
  makefile: 'makefile',
  gemfile: 'ruby',
  procfile: 'bash',
};

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

function getLanguage(extension: string, path: string): string | undefined {
  const normalizedExtension = extension.toLowerCase();
  if (LANGUAGE_BY_EXTENSION[normalizedExtension]) return LANGUAGE_BY_EXTENSION[normalizedExtension];

  const filename = path.split('/').pop()?.toLowerCase() ?? '';
  return LANGUAGE_BY_FILENAME[filename];
}

function highlightLine(line: string, language?: string): string {
  if (!language) return escapeHtml(line);

  try {
    return hljs.highlight(line, { language, ignoreIllegals: true }).value;
  } catch {
    return escapeHtml(line);
  }
}

export default function HighlightedCode({
  content,
  extension,
  path,
  maxLines = 2000,
  renderLimitNotice,
}: HighlightedCodeProps) {
  const lines = content.split('\n');
  const visibleLines = lines.slice(0, maxLines);
  const isTruncated = lines.length > visibleLines.length;
  const lineNumWidth = String(lines.length).length;
  const language = getLanguage(extension, path);
  const renderedLines = visibleLines.map((line) => highlightLine(line, language));

  return (
    <>
      {isTruncated && (
        <div className="code-render-notice">
          {renderLimitNotice ?? `仅渲染前 ${maxLines} 行，共 ${lines.length} 行。`}
        </div>
      )}
      <pre><code className={language ? `hljs language-${language}` : 'hljs'}>
        {renderedLines.map((line, index) => (
          <div className="code-line" key={`${path}-${index}`}>
            <span className="code-line-num">{String(index + 1).padStart(lineNumWidth, ' ')}</span>
            <span
              className="code-line-content"
              dangerouslySetInnerHTML={{ __html: line }}
            />
          </div>
        ))}
      </code></pre>
    </>
  );
}
