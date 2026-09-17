'use client';

import { useTranslation } from 'react-i18next';
import type { CapabilityAxis } from '@/app/package/[name]/detail-view-model';

const TONE_FILL: Record<string, string> = {
  safe: 'var(--color-success)',
  caution: 'var(--color-warning)',
  danger: 'var(--color-danger)',
};

const TONE_RANK: Record<string, number> = { safe: 0, caution: 1, danger: 2 };
/** 常见雷达图的刻度网格；0.5 / 1.0 是数据会落到的两档，描边更重一些 */
const RING_LEVELS = [0.25, 0.5, 0.75, 1];
const TIER_LEVELS = new Set([0.5, 1]);

const LEGEND_DOT_SIZE = 12;

export interface CapabilityRadarProps {
  axes: CapabilityAxis[];
  packageName: string;
  size?: number;
}

export default function CapabilityRadar({
  axes,
  packageName,
  size = 260,
}: CapabilityRadarProps) {
  const { t } = useTranslation();

  if (axes.length < 3) return null;

  const overallTone = axes.reduce(
    (worst, axis) => (TONE_RANK[axis.tone] > TONE_RANK[worst] ? axis.tone : worst),
    'safe',
  );
  // 画布比雷达本身宽：轴标签要横向伸出去，viewBox 必须留出这段空间，否则会被裁掉。
  const center = size / 2;
  const radius = size / 2 - size * 0.115;
  const labelRadius = radius + size * 0.055;
  const paddingX = size * 0.23;
  const paddingY = size * 0.077;
  const viewBox = [
    -paddingX,
    -paddingY,
    size + paddingX * 2,
    size + paddingY * 2,
  ].join(' ');
  const canvasWidth = size + paddingX * 2;
  const canvasHeight = size + paddingY * 2;
  const angleAt = (index: number) => (Math.PI * 2 * index) / axes.length - Math.PI / 2;
  const pointAt = (index: number, distance: number) => ({
    x: center + Math.cos(angleAt(index)) * distance,
    y: center + Math.sin(angleAt(index)) * distance,
  });
  const polygon = (fraction: (index: number) => number) =>
    axes
      .map((_, index) => {
        const { x, y } = pointAt(index, radius * fraction(index));
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      })
      .join(' ');

  return (
    <figure className="capability-radar" data-testid="capability-radar">
      <div className="capability-radar-heading">{t('detail.capability.radar_title')}</div>
      <svg
        viewBox={viewBox}
        width={canvasWidth}
        height={canvasHeight}
        aria-hidden="true"
        focusable="false"
      >
        {RING_LEVELS.map((level) => (
          <polygon
            key={level}
            points={polygon(() => level)}
            className={`capability-radar-ring${TIER_LEVELS.has(level) ? ' is-tier' : ''}`}
          />
        ))}
        {axes.map((axis, index) => {
          const { x, y } = pointAt(index, radius);
          return (
            <line
              key={axis.key}
              x1={center}
              y1={center}
              x2={x}
              y2={y}
              className="capability-radar-spoke"
            />
          );
        })}
        <polygon
          points={polygon((index) => axes[index].value)}
          className={`capability-radar-area tone-${overallTone}`}
        />
        <circle cx={center} cy={center} r={1.5} className="capability-radar-centre" />
        {axes.map((axis, index) =>
          axis.value > 0 ? (
            <circle
              key={axis.key}
              cx={pointAt(index, radius * axis.value).x}
              cy={pointAt(index, radius * axis.value).y}
              r={3.5}
              className="capability-radar-vertex"
              fill={TONE_FILL[axis.tone]}
            >
              <title>
                {`${t(`detail.capability.axis.${axis.key}`)}：${t(axis.detailKey, axis.detailValues)}`}
              </title>
            </circle>
          ) : null,
        )}
        {axes.map((axis, index) => {
          const { x, y } = pointAt(index, labelRadius);
          const horizontal = Math.cos(angleAt(index));
          const anchor = horizontal > 0.3 ? 'start' : horizontal < -0.3 ? 'end' : 'middle';
          return (
            <text
              key={axis.key}
              data-axis={axis.key}
              data-scope={axis.scope}
              x={x}
              y={y}
              textAnchor={anchor}
              dominantBaseline="middle"
              className={`capability-radar-label${axis.scope === 'none' ? ' is-empty' : ''}`}
            >
              {t(`detail.capability.axis.${axis.key}`)}
            </text>
          );
        })}
      </svg>
      <p className="capability-radar-note">{t('detail.capability.radar_note')}</p>
      <ul className="capability-radar-legend">
        <li>
          <span
            className={`capability-radar-legend-dot tone-${overallTone}`}
            style={{ width: LEGEND_DOT_SIZE, height: LEGEND_DOT_SIZE }}
            aria-hidden="true"
          />
          {t('detail.capability.legend.current')}
        </li>
        <li>
          <span
            className="capability-radar-legend-dot is-reference"
            style={{ width: LEGEND_DOT_SIZE, height: LEGEND_DOT_SIZE }}
            aria-hidden="true"
          />
          {t('detail.capability.legend.reference')}
        </li>
      </ul>
      <table className="visually-hidden">
        <caption>{t('detail.capability.radar_aria', { name: packageName })}</caption>
        <thead>
          <tr>
            <th scope="col">{t('detail.capability.axis_header')}</th>
            <th scope="col">{t('detail.capability.value_header')}</th>
          </tr>
        </thead>
        <tbody>
          {axes.map((axis) => (
            <tr key={axis.key}>
              <th scope="row">{t(`detail.capability.axis.${axis.key}`)}</th>
              <td>{t(axis.detailKey, axis.detailValues)}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </figure>
  );
}
