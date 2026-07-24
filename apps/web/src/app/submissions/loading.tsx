export default function SubmissionsLoading() {
  return (
    <div className="status-page">
      <div className="status-header">
        <div className="skeleton">
          <div className="skeleton-bar" style={{ width: '10rem', height: '2rem' }} />
        </div>
        <div className="skeleton" style={{ marginTop: '0.5rem' }}>
          <div className="skeleton-bar" style={{ width: '16rem' }} />
        </div>
      </div>
      <div style={{ maxWidth: '720px', margin: '0 auto' }}>
        {Array.from({ length: 4 }).map((_, i) => (
          <div
            key={i}
            className="skeleton"
            style={{
              background: 'var(--color-paper-2)',
              borderRadius: 'var(--radius-lg)',
              padding: '1.25rem 1.5rem',
              marginBottom: '0.75rem',
              border: '1px solid var(--color-rule)',
            }}
          >
            <div className="skeleton-bar" style={{ width: '12rem', height: '1.2rem' }} />
            <div className="skeleton-bar" style={{ width: '18rem', marginTop: '0.5rem' }} />
          </div>
        ))}
      </div>
    </div>
  );
}
