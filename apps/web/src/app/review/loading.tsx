export default function ReviewLoading() {
  return (
    <div className="review-page">
      <div className="review-header">
        <div className="skeleton">
          <div className="skeleton-bar" style={{ width: '12rem', height: '2rem' }} />
        </div>
        <div className="skeleton" style={{ marginTop: '0.5rem' }}>
          <div className="skeleton-bar" style={{ width: '16rem' }} />
        </div>
      </div>
      <div className="review-table-wrapper skeleton">
        {Array.from({ length: 5 }).map((_, i) => (
          <div key={i} className="skeleton-block" style={{ height: '3.5rem' }} />
        ))}
      </div>
    </div>
  );
}
