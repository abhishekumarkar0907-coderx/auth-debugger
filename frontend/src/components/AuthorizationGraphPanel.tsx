import React, { useMemo } from 'react';
import type {
  AuthorizationGraphEdge,
  AuthorizationGraphNode,
  TraceGraphResponse,
} from '../types.ts';

interface AuthorizationGraphPanelProps {
  graph: TraceGraphResponse | null;
  error: string | null;
}

const NODE_WIDTH = 160;
const NODE_HEIGHT = 76;
const COLUMN_GAP = 178;
const ROW_GAP = 112;
const PADDING = 24;

function nodeAuthority(node: AuthorizationGraphNode): string {
  const permissions = node.authority ?? node.required_authority ?? [];
  return permissions.length > 0 ? permissions.join(', ') : node.service ?? '';
}

function edgeAuthority(edge: AuthorizationGraphEdge): string {
  const permissions = edge.delegated_authority ?? edge.service_authority ?? [];
  return permissions.join(', ');
}

export const AuthorizationGraphPanel: React.FC<AuthorizationGraphPanelProps> = ({
  graph,
  error,
}) => {
  const layout = useMemo(() => {
    if (!graph) return null;

    const nodeById = new Map(graph.nodes.map((node) => [node.id, node]));
    const layers = new Map(graph.nodes.map((node) => [node.id, 0]));
    const indegree = new Map(graph.nodes.map((node) => [node.id, 0]));
    const outgoing = new Map<string, string[]>();

    for (const edge of graph.edges) {
      if (!nodeById.has(edge.source) || !nodeById.has(edge.target)) continue;
      outgoing.set(edge.source, [...(outgoing.get(edge.source) ?? []), edge.target]);
      indegree.set(edge.target, (indegree.get(edge.target) ?? 0) + 1);
    }

    const queue = graph.nodes
      .filter((node) => indegree.get(node.id) === 0)
      .map((node) => node.id);
    const visited = new Set<string>();

    while (queue.length > 0) {
      const source = queue.shift()!;
      visited.add(source);
      for (const target of outgoing.get(source) ?? []) {
        layers.set(target, Math.max(layers.get(target) ?? 0, (layers.get(source) ?? 0) + 1));
        const remaining = (indegree.get(target) ?? 0) - 1;
        indegree.set(target, remaining);
        if (remaining === 0) queue.push(target);
      }
    }

    if (visited.size < graph.nodes.length) {
      const nextLayer = Math.max(0, ...layers.values()) + 1;
      graph.nodes.forEach((node) => {
        if (!visited.has(node.id)) layers.set(node.id, nextLayer);
      });
    }

    const nodesByLayer = new Map<number, AuthorizationGraphNode[]>();
    for (const node of graph.nodes) {
      const layer = layers.get(node.id) ?? 0;
      nodesByLayer.set(layer, [...(nodesByLayer.get(layer) ?? []), node]);
    }

    const positions = new Map<string, { x: number; y: number }>();
    let maxRows = 1;
    for (const [layer, nodes] of nodesByLayer) {
      maxRows = Math.max(maxRows, nodes.length);
      nodes.forEach((node, row) => {
        positions.set(node.id, {
          x: PADDING + layer * COLUMN_GAP,
          y: PADDING + row * ROW_GAP,
        });
      });
    }

    const layerCount = Math.max(0, ...nodesByLayer.keys()) + 1;
    return {
      positions,
      width: Math.max(560, PADDING * 2 + NODE_WIDTH + (layerCount - 1) * COLUMN_GAP),
      height: PADDING * 2 + (maxRows - 1) * ROW_GAP + NODE_HEIGHT,
    };
  }, [graph]);

  const nodes = graph?.nodes ?? [];
  const edges = graph?.edges ?? [];
  const nodeById = new Map(nodes.map((node) => [node.id, node]));

  return (
    <section className="authorization-graph-panel" aria-labelledby="authorization-graph-title">
      <div className="authorization-graph-heading">
        <div>
          <span className="security-analysis-eyebrow">Trace relationships</span>
          <h3 id="authorization-graph-title">Authorization graph</h3>
        </div>
        {graph && (
          <span className="authorization-graph-count">
            {nodes.length} nodes · {edges.length} links
          </span>
        )}
      </div>

      {error ? (
        <p className="security-analysis-unavailable">{error}</p>
      ) : graph && nodes.length > 0 && layout ? (
        <>
          <div className="authorization-graph-canvas">
            <svg
              className="authorization-graph-svg"
              viewBox={`0 0 ${layout.width} ${layout.height}`}
              role="img"
              aria-label={`Authorization graph with ${nodes.length} nodes and ${edges.length} links`}
            >
              <defs>
                <marker
                  id="authorization-graph-arrow"
                  markerWidth="8"
                  markerHeight="8"
                  refX="7"
                  refY="4"
                  orient="auto"
                >
                  <path d="M0,0 L8,4 L0,8 z" className="authorization-graph-arrowhead" />
                </marker>
              </defs>
              {edges.map((edge, index) => {
                const source = layout.positions.get(edge.source);
                const target = layout.positions.get(edge.target);
                if (!source || !target) return null;
                const startX = source.x + NODE_WIDTH;
                const startY = source.y + NODE_HEIGHT / 2;
                const endX = target.x;
                const endY = target.y + NODE_HEIGHT / 2;
                const controlX = (startX + endX) / 2;
                return (
                  <path
                    key={`${edge.source}-${edge.target}-${index}`}
                    d={`M ${startX} ${startY} C ${controlX} ${startY}, ${controlX} ${endY}, ${endX} ${endY}`}
                    className={`authorization-graph-edge authorization-graph-edge-${edge.type}`}
                    markerEnd="url(#authorization-graph-arrow)"
                  />
                );
              })}
              {nodes.map((node) => {
                const position = layout.positions.get(node.id);
                if (!position) return null;
                const subtitle = nodeAuthority(node);
                const label =
                  node.label.length > 20 ? `${node.label.slice(0, 17)}…` : node.label;
                return (
                  <g
                    key={node.id}
                    className={`authorization-graph-node authorization-graph-node-${node.type}`}
                    transform={`translate(${position.x} ${position.y})`}
                  >
                    <rect width={NODE_WIDTH} height={NODE_HEIGHT} rx="10" />
                    <text x="12" y="22" className="authorization-graph-node-type">
                      {node.type}
                    </text>
                    <text x="12" y="43" className="authorization-graph-node-label">
                      {label}
                    </text>
                    {subtitle && (
                      <text x="12" y="61" className="authorization-graph-node-subtitle">
                        {subtitle.length > 22 ? `${subtitle.slice(0, 19)}…` : subtitle}
                      </text>
                    )}
                  </g>
                );
              })}
            </svg>
          </div>
          {edges.length > 0 && (
            <details className="authorization-graph-link-details">
              <summary>Inspect graph links ({edges.length})</summary>
              <ul className="authorization-graph-links" aria-label="Authorization graph links">
                {edges.map((edge, index) => (
                  <li key={`${edge.source}-${edge.target}-${index}`}>
                    <strong>{nodeById.get(edge.source)?.label ?? edge.source}</strong>
                    <span aria-hidden="true">→</span>
                    <strong>{nodeById.get(edge.target)?.label ?? edge.target}</strong>
                    <span className="authorization-graph-link-type">{edge.type}</span>
                    {edge.credential_type && (
                      <span className="authorization-graph-link-type">{edge.credential_type}</span>
                    )}
                    {edgeAuthority(edge) && (
                      <span className="authorization-graph-link-authority">
                        {edgeAuthority(edge)}
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            </details>
          )}
        </>
      ) : graph ? (
        <p className="security-analysis-unavailable">
          This trace has no authorization graph nodes or links.
        </p>
      ) : (
        <p className="security-analysis-unavailable">
          Authorization graph is not available.
        </p>
      )}
    </section>
  );
};
