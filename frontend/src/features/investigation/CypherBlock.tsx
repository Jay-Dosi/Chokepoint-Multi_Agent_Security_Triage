/** A tinted Cypher statement with a copy control. Four tones, no rainbow. */

import { useState } from 'react';

import { Button } from '../../components/Button';
import { TOKEN_CLASS, tintCypher } from '../../lib/cypherTint';

interface CypherBlockProps {
  cypher: string;
  index?: number;
}

export function CypherBlock({ cypher, index }: CypherBlockProps) {
  const [copied, setCopied] = useState(false);
  const tokens = tintCypher(cypher);

  const copy = async () => {
    try {
      await navigator.clipboard.writeText(cypher);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      setCopied(false);
    }
  };

  return (
    <div className="cypher-block">
      <div style={{ display: 'flex', alignItems: 'center', gap: 'var(--s-2)', marginBottom: 4 }}>
        <span className="label">{index === undefined ? 'Cypher' : `Cypher ${index + 1}`}</span>
        <Button icon="copy" small variant="quiet" onClick={() => void copy()}>
          {copied ? 'Copied' : 'Copy'}
        </Button>
      </div>
      <pre>
        {tokens.map((token, position) => {
          const className = TOKEN_CLASS[token.kind];
          return className ? (
            <span key={position} className={className}>
              {token.text}
            </span>
          ) : (
            <span key={position}>{token.text}</span>
          );
        })}
      </pre>
    </div>
  );
}
