/** "The graph's view": the top attack paths, or the call to action. */

import { Link } from 'react-router-dom';

import type { AttackPathModel, InvestigationSummary } from '../../api/types';
import { EmptyState } from '../../components/EmptyState';
import { Loading } from '../../components/Loading';
import { Panel } from '../../components/Panel';
import { Button } from '../../components/Button';
import { score } from '../../lib/format';

interface BoardGraphViewProps {
  paths: AttackPathModel[];
  latest: InvestigationSummary | null;
  loading: boolean;
  onStart: () => void;
}

export function BoardGraphView({ paths, latest, loading, onStart }: BoardGraphViewProps) {
  return (
    <Panel
      number="02"
      title="The graph's view"
      right={
        latest ? (
          <Link to={`/i/${latest.id}`} className="mono-sm">
            {latest.id}
          </Link>
        ) : null
      }
      flush
    >
      <div style={{ padding: 'var(--s-3) var(--s-3) 0' }}>
        <p className="mono-sm" style={{ margin: 0 }}>
          Paths from the open internet to a crown jewel, ordered by what they would actually cost you.
        </p>
      </div>
      {loading ? (
        <div style={{ padding: 'var(--s-3)' }}>
          <Loading what="reading paths" />
        </div>
      ) : paths.length === 0 ? (
        <div style={{ padding: 'var(--s-3)' }}>
          <EmptyState
            statement="No investigation has mapped the estate yet."
            detail="An investigation enumerates every internet-to-crown-jewel path, scores it, and names the smallest set of fixes that cuts the most risk."
            action={
              <Button variant="primary" icon="play" onClick={onStart}>
                Triage the latest scan
              </Button>
            }
          />
        </div>
      ) : (
        <div className="path-list">
          {paths.slice(0, 8).map((path) => (
            <Link key={path.id} to={latest ? `/i/${latest.id}` : '/'} className="path-row" style={{ borderBottom: '1px solid var(--rule-soft)' }}>
              <span className="path-chain">{path.nodes.map((node) => node.id).join(' → ')}</span>
              <span className="path-meta">
                <span className="ribbon-score">{score(path.score_pct)}</span>
                {' · '}
                {path.hops} hops
              </span>
            </Link>
          ))}
        </div>
      )}
    </Panel>
  );
}
