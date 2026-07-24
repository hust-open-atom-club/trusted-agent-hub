export default function AdminLoading() {
  return (
    <div className="admin-page">
      <div className="admin-dashboard">
        <div className="admin-dashboard-header">
          <div className="skeleton">
            <div className="skeleton-bar" style={{ width: '14rem', height: '2rem' }} />
          </div>
          <div className="skeleton" style={{ marginTop: '0.5rem' }}>
            <div className="skeleton-bar" style={{ width: '18rem' }} />
          </div>
        </div>
        <div className="admin-stat-grid">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="admin-stat-card skeleton">
              <div className="skeleton-bar" style={{ width: '3rem', height: '2rem', marginBottom: '0.75rem' }} />
              <div className="skeleton-bar" style={{ width: '5rem' }} />
              <div className="skeleton-bar" style={{ width: '8rem', marginTop: '0.5rem' }} />
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
