'use client';

import { Suspense } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';

function ResultContent() {
  const router = useRouter();
  const params = useSearchParams();
  const status = params.get('status');
  const versionId = params.get('version_id');
  const errorMsg = params.get('error');

  const isSuccess = status === 'success';

  return (
    <div className="result-page">
      <div className="result-card">
        {isSuccess ? (
          <>
            <div className="result-icon result-icon-success">&#10004;</div>
            <h1 className="result-title">提交成功！</h1>
            <p className="result-desc">您的 Skill 已成功提交，正在进入安全扫描队列。</p>

            {versionId && (
              <div className="result-version-id">
                <span className="result-label">版本 ID</span>
                <code>{versionId}</code>
              </div>
            )}

            <div className="result-banner">
              <span className="result-banner-icon">&#9888;</span>
              <div>
                <strong>完整状态追踪页面正在建设中</strong>
                <p>后续更新将支持实时查看扫描进度、风险报告详情和审核结论。敬请期待！</p>
              </div>
            </div>

            <div className="result-actions">
              <button className="btn btn-primary" onClick={() => router.push('/submit')}>
                继续提交
              </button>
              <button className="btn btn-secondary" onClick={() => router.push('/')}>
                返回首页
              </button>
            </div>
          </>
        ) : (
          <>
            <div className="result-icon result-icon-error">&#10008;</div>
            <h1 className="result-title">提交失败</h1>
            <p className="result-desc">
              {errorMsg ? decodeURIComponent(errorMsg) : '提交过程中出现错误，请返回重试。'}
            </p>

            <div className="result-banner result-banner-error">
              <span className="result-banner-icon">&#9888;</span>
              <div>
                <strong>常见原因</strong>
                <ul>
                  <li>包名称已被占用，请更换名称后重试</li>
                  <li>GitHub 仓库不可访问，请检查 URL 是否正确</li>
                  <li>版本号格式不符合 SemVer 规范</li>
                </ul>
              </div>
            </div>

            <div className="result-actions">
              <button className="btn btn-primary" onClick={() => router.back()}>
                返回重试
              </button>
              <button className="btn btn-secondary" onClick={() => router.push('/')}>
                返回首页
              </button>
            </div>
          </>
        )}
      </div>
    </div>
  );
}

export default function ResultPage() {
  return (
    <Suspense fallback={<div className="result-page"><div className="result-card"><p>加载中...</p></div></div>}>
      <ResultContent />
    </Suspense>
  );
}
