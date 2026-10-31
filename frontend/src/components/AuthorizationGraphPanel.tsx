import React, { useMemo, useState } from 'react';
import type { InvestigationDataSource } from '../services/investigationApi.ts';
import type { AuthorizationGraphEdge, AuthorizationGraphNode } from '../types.ts';
import './AuthorizationGraphPanel.css';

type GraphState =
  | { kind: 'loading' }
  | { kind: 'empty'; message: string }
  | { kind: 'error'; message: string }
  | {
    kind: 'ready';
    graph: {
      trace_id: string;
      nodes: AuthorizationGraphNode[];
      edges: AuthorizationGraphEdge[];
    };
  };

interface AuthorizationGraphPanelProps {
  state: GraphState;
  dataSource: InvestigationDataSource;
}

type Selection =
  | { kind: 'node'; id: string }
  | { kind: 'edge'; key: string }
  | null;

function edgeKey(edge: AuthorizationGraphEdge, index: number): string {
  return `${edge.source}:${edge.target}:${edge.type}:${index}`;
}

function formatGraphValue(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

export const AuthorizationGraphPanel: React.FC<AuthorizationGraphPanelProps> = ({
  state,
  dataSource,
}) => {
  const [selection, setSelection] = useState<Selection>(null);
  const positions = useMemo(() => {
    if (state.kind !== 'ready') return new Map<string, { x: number; y: number }>();
    const count = state.graph.nodes.length;
    return new Map(state.graph.nodes.map((node, index) => [
      node.id,
      {
        x: count < 2 ? 50 : 8 + (index * 84) / (count - 1),
        y: index % 2 === 0 ? 34 : 66,
      },
    ]));
  }, [state]);

  let selectedValue: { title: string; value: unknown } | null = null;
  if (state.kind === 'ready' && selection?.kind === 'node') {
    const node = state.graph.nodes.find((item) => item.id === selection.id);
    if (node) selectedValue = { title: node.label, value: node };
  } else if (state.kind === 'ready' && selection?.kind === 'edge') {
    const index = state.graph.edges.findIndex((edge, i) => edgeKey(edge, i) === selection.key);
    const edge = index >= 0 ? state.graph.edges[index] : undefined;
    if (edge) selectedValue = { title: `${edge.type}: ${edge.source} → ${edge.target}`, value: edge };
  }

  return (
    <section className="authorization-graph-panel" aria-labelledby="authorization-graph-title">
      <header className="authorization-graph-header">
        <div>
          <p className="security-eyebrow">TRACE RELATIONSHIPS</p>
          <h3 id="authorization-graph-title">Authorization graph</h3>
          {state.kind === 'ready' && <p className="authorization-graph-trace">{state.graph.trace_id}</p>}
        </div>
        <span className={`graph-source-label ${dataSource}`}>
          {dataSource === 'demo' ? 'Sample data' : 'Live API'}
        </span>
      </header>

      {state.kind === 'loading' && <p role="status">Loading authorization graph…</p>}
      {state.kind === 'empty' && <p>{state.message}</p>}
      {state.kind === 'error' && <p role="alert">{state.message}</p>}
      {state.kind === 'ready' && state.graph.nodes.length === 0 && state.graph.edges.length === 0 && (
        <p>No authorization graph entities or relationships were returned for this trace.</p>
      )}
      {state.kind === 'ready' && (state.graph.nodes.length > 0 || state.graph.edges.length > 0) && (
        <>
          <p className="authorization-graph-counts">
            {state.graph.nodes.length} entities · {state.graph.edges.length} relationships
          </p>
          <div className="authorization-graph-canvas">
            <svg
              className="authorization-graph-svg"
              viewBox="0 0 100 100"
              role="group"
              aria-label={`Authorization graph for trace ${state.graph.trace_id}`}
            >
              <defs>
                <marker id="authorization-graph-arrow" viewBox="0 0 8 8" refX="7" refY="4" markerWidth="4" markerHeight="4" orient="auto">
                  <path d="M0 0 L8 4 L0 8 z" />
                </marker>
              </defs>
              {state.graph.edges.map((edge, index) => {
                const from = positions.get(edge.source);
                const to = positions.get(edge.target);
                if (!from || !to) return null;
                const key = edgeKey(edge, index);
                const active = selection?.kind === 'edge' && selection.key === key;
                return (
                  <g
                    key={key}
                    className={`authorization-graph-edge ${active ? 'active' : ''}`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${edge.type}: ${edge.source} to ${edge.target}`}
                    onClick={() => setSelection({ kind: 'edge', key })}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelection({ kind: 'edge', key });
                      }
                    }}
                  >
                    <line className="authorization-graph-hit-area" x1={from.x} y1={from.y} x2={to.x} y2={to.y} />
                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y} markerEnd="url(#authorization-graph-arrow)" />
                    <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 2}>{edge.type}</text>
                  </g>
                );
              })}
              {state.graph.nodes.map((node) => {
                const point = positions.get(node.id);
                if (!point) return null;
                const active = selection?.kind === 'node' && selection.id === node.id;
                return (
                  <g
                    key={node.id}
                    className={`authorization-graph-node ${active ? 'active' : ''}`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${node.label}, ${node.type}`}
                    onClick={() => setSelection({ kind: 'node', id: node.id })}
                    onKeyDown={(event) => {
                      if (event.key === 'Enter' || event.key === ' ') {
                        event.preventDefault();
                        setSelection({ kind: 'node', id: node.id });
                      }
                    }}
                  >
                    <title>{node.label} ({node.type})</title>
                    <circle cx={point.x} cy={point.y} r="4.3" />
                    <text x={point.x} y={point.y + 9}>{node.label}</text>
                  </g>
                );
              })}
            </svg>
          </div>
          {selectedValue
            ? <div className="authorization-graph-selection">
              <h4>{selectedValue.title}</h4>
              <pre>{formatGraphValue(selectedValue.value)}</pre>
            </div>
            : <p className="authorization-graph-hint">Select a node or relationship to inspect the backend response.</p>}
        </>
      )}
    </section>
  );
};
